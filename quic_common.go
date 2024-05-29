package clienthellod

import (
	"bytes"
	"errors"
	"io"

	"github.com/gaukas/clienthellod/internal/utils"
	"golang.org/x/crypto/cryptobyte"
)

// ReadNextVLI unpacks the next variable-length integer from the given
// io.Reader. It returns the decoded value and the number of bytes read.
// For example:
//
//	0x0a -> 0xa, 1
//	0x80 0x10 0x00 0x00 -> 0x100000, 4
func ReadNextVLI(r io.Reader) (val uint64, n int, err error) {
	// read the first byte
	var encodedBytes []byte = make([]byte, 1)
	_, err = r.Read(encodedBytes)
	if err != nil {
		return 0, 0, err
	}

	// check MSBs of the first byte
	switch encodedBytes[0] & 0xc0 { // 0xc0 = 0b11000000, when the first 2 bits in a byte is set
	case 0x00:
		n = 1
	case 0x40:
		n = 2
	case 0x80:
		n = 4
	case 0xc0:
		n = 8
	default:
		return 0, 0, errors.New("invalid first byte")
	}

	// read the rest bytes
	if n > 1 {
		encodedBytes = append(encodedBytes, make([]byte, n-1)...)
		_, err = r.Read(encodedBytes[1:])
		if err != nil {
			return 0, 0, err
		}
	}

	// decode
	encodedBytes[0] &= 0x3f // 0x3f = 0b00111111, clear MSBs
	for i := 0; i < n; i++ {
		val <<= 8
		val |= uint64(encodedBytes[i])
	}

	return
}

func DecodeVLI(vli []byte) (val uint64, err error) {
	var n int
	val, n, err = ReadNextVLI(bytes.NewReader(vli))
	if err != nil {
		return 0, err
	}
	if n != len(vli) {
		return 0, errors.New("invalid VLI length")
	}
	return
}

func unsetVLIBits(vli []byte) {
	if UNSET_VLI_BITS {
		vli[0] &= 0x3f // 0x3f = 0b00111111, clear MSBs
	}
}

func IsGREASETransportParameter(paramType uint64) bool {
	return paramType >= 27 && (paramType-27)%31 == 0 // reserved values are 27, 58, 89, ...
}

var (
	ErrNotQUICLongHeaderFormat = errors.New("not a QUIC Long Header Format Packet")
	ErrNotQUICInitialPacket    = errors.New("not a QUIC Initial Packet")
)

// DecodeQUICHeaderAndFrames decodes a QUIC initial packet and returns a QUICHeader.
func DecodeQUICHeaderAndFrames(p []byte) (hdr *QUICHeader, frames QUICFrames, err error) { // skipcq: GO-R1005
	if len(p) < 7 { // at least 7 bytes before TokenLength
		return nil, nil, errors.New("packet too short")
	}

	// make a copy of the packet, so we can use it for crypto later
	recdata := make([]byte, len(p))
	copy(recdata, p)

	hdr = &QUICHeader{}

	packetHeaderByteProtected := p[0]

	// check if it's in QUIC long header format:
	// - MSB highest bit is 1 (long header format)
	// - MSB 2nd highest bit is 1 (always set for QUIC)
	if packetHeaderByteProtected&0xc0 != 0xc0 {
		return nil, nil, ErrNotQUICLongHeaderFormat
	}

	// check if it's a QUIC Initial Packet: MSB lower 2 bits are 0
	if packetHeaderByteProtected&0x30 != 0 {
		return nil, nil, ErrNotQUICInitialPacket
	}

	// LSB of the first byte is protected, we will resolve it later

	hdr.Version = make(utils.Uint8Arr, 4)
	copy(hdr.Version, p[1:5])
	s := cryptobyte.String(p[5:])
	initialRandom := new(cryptobyte.String)
	if !s.ReadUint8LengthPrefixed(initialRandom) {
		return nil, nil, errors.New("failed to read DCID (initial random)")
	}
	hdr.DCIDLength = uint32(len(*initialRandom))

	var scidLenUint8 uint8
	if !s.ReadUint8(&scidLenUint8) ||
		!s.Skip(int(scidLenUint8)) {
		return nil, nil, errors.New("failed to read SCID")
	}
	hdr.SCIDLength = uint32(scidLenUint8)

	// token length is a VLI
	r := bytes.NewReader(s)
	tokenLen, _, err := ReadNextVLI(r)
	if err != nil {
		return nil, nil, err
	}
	// read token bytes
	token := make([]byte, tokenLen)
	n, err := r.Read(token)
	if err != nil {
		return nil, nil, err
	}
	if n != int(tokenLen) {
		return nil, nil, errors.New("failed to read all token bytes, short read")
	}
	if tokenLen > 0 {
		hdr.HasToken = true
	}

	// packet length is a VLI
	packetLen, _, err := ReadNextVLI(r)
	if err != nil {
		return nil, nil, err
	}
	if packetLen < 20 {
		return nil, nil, errors.New("packet length too short, ignore")
	}

	// read all remaining bytes as payload
	payload := make([]byte, packetLen)
	n, err = r.Read(payload)
	if err != nil {
		return nil, nil, err
	}
	if n != int(packetLen) {
		return nil, nil, errors.New("failed to read all payload bytes, short read")
	}

	// do key calculation
	clientKey, clientIV, clientHpKey, err := ClientInitialKeysCalc(*initialRandom)
	if err != nil {
		return nil, nil, err
	}

	// compute header protection
	hp, err := ComputeHeaderProtection(clientHpKey, payload[4:20])
	if err != nil {
		return nil, nil, err
	}

	// prepare recdata
	// truncate recdata to remove following (possibly) padding bytes
	recdata = recdata[:len(recdata)-r.Len()]
	// remove payload bytes
	recdata = recdata[:len(recdata)-len(payload)] // recdata: [...headers...] [packet number]

	// decipher packet header byte
	headerByte := packetHeaderByteProtected ^ (hp[0] & 0x0f) // only lower 4 bits are protected and thus need to be XORed
	recdata[0] = headerByte
	hdr.initialPacketNumberLength = uint32(headerByte&0x03) + 1 // LSB lower 2 bits are packet number length (-1)
	packetNumberBytes := payload[:hdr.initialPacketNumberLength]
	for i, b := range packetNumberBytes {
		unprotectedByte := b ^ hp[i+1]
		recdata = append(recdata, unprotectedByte)
		hdr.initialPacketNumber = hdr.initialPacketNumber<<8 + uint64(unprotectedByte)
		hdr.PacketNumber = append(hdr.PacketNumber, unprotectedByte)
	}

	cipherPayload := payload[hdr.initialPacketNumberLength : len(payload)-16] // payload: [packet number (i-byte)] [encrypted data] [auth tag (16-byte)]
	authTag := payload[len(payload)-16:]

	// decipher payload
	plainPayload, err := DecryptAES128GCM(clientIV, hdr.initialPacketNumber, clientKey, cipherPayload, recdata, authTag)
	if err != nil {
		return nil, nil, err
	}

	// parse frames
	frames, err = ReadAllFrames(bytes.NewBuffer(plainPayload))
	if err != nil {
		return nil, nil, err
	}

	// // deduplicate frame IDs
	// qHdr.FrameIDs = utils.DedupIntArr(qHdr.FrameIDs)

	return
}
