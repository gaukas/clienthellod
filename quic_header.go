package clienthellod

import (
	"bytes"
	"errors"
	"sort"

	"github.com/gaukas/clienthellod/internal/utils"
	"golang.org/x/crypto/cryptobyte"
)

var (
	ErrNotQUICLongHeaderFormat = errors.New("packet is not in QUIC Long Header Format")
	ErrNotQUICInitialPacket    = errors.New("packet is not a QUIC Initial Packet")
)

type QUICHeader struct {
	InitialPacketNumberLength uint32         `json:"pn_len,omitempty"`  // TODO: from Packet Header Byte, +1 or not?
	VersionLength             uint32         `json:"ver_len,omitempty"` // TODO: is it not fixed 4-byte?
	Version                   utils.Uint8Arr `json:"version,omitempty"` // 4-byte version
	DCIDLength                uint32         `json:"dcid_len,omitempty"`
	SCIDLength                uint32         `json:"scid_len,omitempty"`
	TokenLength               uint32         `json:"token_len,omitempty"`
	InitialPacketNumber       uint32         `json:"pn,omitempty"` // TODO: protected or unprotected?

	// These two fields are not strictly part of QUIC header, but we need them before parsing QUIC ClientHello
	FramesPresentLength uint32   `json:"frames_present_len,omitempty"` // TODO: length of all frames OR number of frames?
	FrameIDs            []uint32 `json:"frame_id,omitempty"`           // sorted
	frames              []Frame
}

func DecodeQUICHeaderAndFrames(p []byte) (*QUICHeader, error) {
	// make a copy of the packet, so we can use it for crypto later
	var recdata = make([]byte, len(p))
	copy(recdata, p)

	var qHdr *QUICHeader = &QUICHeader{}

	packetHeaderByteProtected := p[0]

	// check if it's in QUIC long header format:
	// - MSB highest bit is 1 (long header format)
	// - MSB 2nd highest bit is 1 (always set for QUIC)
	if packetHeaderByteProtected&0xc0 != 0xc0 {
		return nil, ErrNotQUICLongHeaderFormat
	}

	// check if it's a QUIC Initial Packet: MSB lower 2 bits are 0
	if packetHeaderByteProtected&0x30 != 0 {
		return nil, ErrNotQUICInitialPacket
	}

	// LSB of the first byte is protected, we will resolve it later

	// TODO: QUIC Version is always 4-byte, right?
	qHdr.VersionLength = 4
	qHdr.Version = p[1:5]

	s := cryptobyte.String(p[5:])
	initialRandom := new(cryptobyte.String)
	if !s.ReadUint8LengthPrefixed(initialRandom) {
		return nil, errors.New("failed to read DCID (initial random)")
	}
	qHdr.DCIDLength = uint32(len(*initialRandom))

	var scidLenUint8 uint8
	if !s.ReadUint8(&scidLenUint8) ||
		!s.Skip(int(scidLenUint8)) {
		return nil, errors.New("failed to read SCID")
	}
	qHdr.SCIDLength = uint32(scidLenUint8)

	// token length is a VLI
	r := bytes.NewReader(s)
	tokenLen, _, err := ReadNextVLI(r)
	if err != nil {
		return nil, err
	}
	qHdr.TokenLength = uint32(tokenLen)

	// read token bytes
	token := make([]byte, qHdr.TokenLength)
	n, err := r.Read(token)
	if err != nil {
		return nil, err
	}
	if n != int(tokenLen) {
		return nil, errors.New("failed to read all token bytes, short read")
	}

	// packet length is a VLI
	packetLen, _, err := ReadNextVLI(r)
	if err != nil {
		return nil, err
	}

	// read all remaining bytes as payload
	payload := make([]byte, packetLen)
	n, err = r.Read(payload)
	if err != nil {
		return nil, err
	}
	if n != int(packetLen) {
		return nil, errors.New("failed to read all payload bytes, short read")
	}

	// do key calculation
	clientKey, clientIV, clientHpKey, err := ClientInitialKeysCalc(*initialRandom)
	if err != nil {
		return nil, err
	}

	// compute header protection
	hp, err := ComputeHeaderProtection(clientHpKey, payload[4:20])
	if err != nil {
		return nil, err
	}

	// prepare recdata
	recdata = recdata[:len(recdata)-len(payload)] // recdata: [...headers...] [packet number]

	// decipher packet header byte
	headerByte := packetHeaderByteProtected ^ (hp[0] & 0x0f) // only lower 4 bits are protected and thus need to be XORed
	recdata[0] = headerByte
	qHdr.InitialPacketNumberLength = uint32(headerByte&0x03) + 1 // LSB lower 2 bits are packet number length (-1)
	packetNumberBytes := payload[:qHdr.InitialPacketNumberLength]
	for i, b := range packetNumberBytes {
		unprotectedByte := b ^ hp[i+1]
		recdata = append(recdata, unprotectedByte)
		qHdr.InitialPacketNumber = qHdr.InitialPacketNumber<<8 + uint32(unprotectedByte)
	}

	ciphertext := payload[qHdr.InitialPacketNumberLength : len(payload)-16] // payload: [packet number (i-byte)] [encrypted data] [auth tag (16-byte)]
	authTag := payload[len(payload)-16:]

	// decipher payload
	plaintext, err := DecryptAES128GCM(clientIV, uint64(qHdr.InitialPacketNumber), clientKey, ciphertext, recdata, authTag)
	if err != nil {
		return nil, err
	}
	qHdr.FramesPresentLength = uint32(len(plaintext))

	// parse frames
	qHdr.frames, err = ReadAllFrames(bytes.NewBuffer(plaintext))
	if err != nil {
		return nil, err
	}

	for _, f := range qHdr.frames {
		qHdr.FrameIDs = append(qHdr.FrameIDs, uint32(f.FrameType()))
		// qHdr.FramesPresentLength++
	}

	// sort frame IDs
	sort.Slice(qHdr.FrameIDs, func(i, j int) bool {
		return qHdr.FrameIDs[i] < qHdr.FrameIDs[j]
	})

	return qHdr, nil
}
