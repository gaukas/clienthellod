package clienthellod

import (
	"fmt"
	"io"
	"sort"

	"github.com/gaukas/clienthellod/internal/utils"
)

const (
	QUICFrame_PADDING uint64 = 0 // 0
	QUICFrame_PING    uint64 = 1 // 1
	QUICFrame_CRYPTO  uint64 = 6 // 6
)

// QUICFrame is the interface that wraps the basic methods of a QUIC frame.
type QUICFrame interface {
	// FrameType returns the type of the frame.
	FrameType() uint64

	// ReadReader takes a Reader and reads the rest of the frame from it,
	// starting from the first byte after the frame type.
	//
	// The returned io.Reader contains the rest of the frame, it could be
	// the input Reader itself (if no extra bytes are read) or a rewinded
	// Reader (if extra bytes are read and rewinding is needed).
	ReadReader(io.Reader) (io.Reader, error)
}

// ReadAllFrames reads all QUIC frames from the input reader.
func ReadAllFrames(r io.Reader) ([]QUICFrame, error) {
	var frames []QUICFrame = make([]QUICFrame, 0)

	for {
		// QUICFrame Type
		frameType, _, err := ReadNextVLI(r)
		if err != nil {
			if err == io.EOF {
				return frames, nil
			}
			return nil, err
		}

		// QUICFrame
		var frame QUICFrame
		switch frameType {
		case QUICFrame_PADDING:
			frame = &PADDING{}
		case QUICFrame_PING:
			frame = &PING{}
		case QUICFrame_CRYPTO:
			frame = &CRYPTO{}
		default:
			return nil, fmt.Errorf("unknown frame type: 0x%.2x", frameType)
		}

		// Read the rest of the frame
		r, err = frame.ReadReader(r)
		if err != nil {
			return nil, err
		}

		// Append the frame
		frames = append(frames, frame)
	}
}

// ReassembleCRYPTOFrames reassembles CRYPTO frames into a single byte slice that
// consists of the entire CRYPTO data.
func ReassembleCRYPTOFrames(frames []QUICFrame) ([]byte, error) {
	var cryptoFrames []QUICFrame = make([]QUICFrame, 0)

	// Collect all CRYPTO frames
	for _, frame := range frames {
		if frame.FrameType() == QUICFrame_CRYPTO {
			cryptoFrames = append(cryptoFrames, frame)
		}
	}

	if len(cryptoFrames) == 0 {
		return nil, nil // no CRYPTO frames is not an error
	}

	// Sort CRYPTO frames by offset
	sort.Slice(cryptoFrames, func(i, j int) bool {
		return cryptoFrames[i].(*CRYPTO).Offset < cryptoFrames[j].(*CRYPTO).Offset
	})

	// Reassemble CRYPTO frames
	var reassembled []byte = make([]byte, 0)
	for _, frame := range cryptoFrames {
		if uint64(len(reassembled)) == frame.(*CRYPTO).Offset {
			reassembled = append(reassembled, frame.(*CRYPTO).data...)
		} else {
			return nil, fmt.Errorf("failed to reassemble CRYPTO frames")
		}
	}

	return reassembled, nil
}

// QUICFrames is a slice of QUICFrame.
type QUICFrames []QUICFrame

// FrameTypes returns the frame types of all QUIC frames.
func (qfs QUICFrames) FrameTypes() []uint64 {
	var frameTypes []uint64 = make([]uint64, 0)

	for _, f := range qfs {
		frameTypes = append(frameTypes, f.FrameType())
	}

	return frameTypes
}

// FrameTypesUint8 returns the frame types of all QUIC frames as uint8.
func (qfs QUICFrames) FrameTypesUint8() []uint8 {
	var frameTypesUint8 []uint8 = make([]uint8, 0)

	for _, f := range qfs {
		frameTypesUint8 = append(frameTypesUint8, uint8(f.FrameType()&0xFF))
	}

	return frameTypesUint8
}

// PADDING frame
type PADDING struct {
	Length uint64 `json:"length,omitempty"` // count 0x00 bytes until not 0x00
}

// FrameType implements QUICFrame interface.
func (*PADDING) FrameType() uint64 {
	return QUICFrame_PADDING
}

// ReadFrom implements QUICFrame interface. It keeps reading until it finds a
// non-zero byte, then the non-zero byte is rewinded back to the reader and
// the reader is returned.
func (f *PADDING) ReadReader(r io.Reader) (rr io.Reader, err error) {
	f.Length = 1 // starting from 1, since type is already read

	var b []byte = make([]byte, 1)
	for {
		_, err = r.Read(b)
		if err != nil {
			if err == io.EOF {
				return r, nil // EOF is not an error, it just means all frames are read
			}
			return r, err
		}
		if b[0] != 0x00 {
			// rewind the reader
			rr = utils.RewindReader(r, b)
			return
		}
		f.Length++
	}
}

// PING frame
type PING struct{}

// FrameType implements QUICFrame interface.
func (*PING) FrameType() uint64 {
	return QUICFrame_PING
}

// ReadFrom implements QUICFrame interface. It does nothing and returns the
// input reader.
func (*PING) ReadReader(r io.Reader) (rr io.Reader, err error) {
	return r, nil
}

// CRYPTO frame
type CRYPTO struct {
	Offset uint64 `json:"offset,omitempty"` // offset of crypto data, from VLI
	Length uint64 `json:"length,omitempty"` // length of crypto data, from VLI
	// DataIn []byte `json:"data,omitempty"`   // TODO: input crypto data, used for unmarshal only
	data []byte
}

// FrameType implements QUICFrame interface.
func (*CRYPTO) FrameType() uint64 {
	return QUICFrame_CRYPTO
}

// ReadFrom implements QUICFrame interface. It reads the offset, length and
// crypto data from the input reader.
func (f *CRYPTO) ReadReader(r io.Reader) (rr io.Reader, err error) {
	// Offset
	f.Offset, _, err = ReadNextVLI(r)
	if err != nil {
		return r, err
	}

	// Length
	f.Length, _, err = ReadNextVLI(r)
	if err != nil {
		return r, err
	}

	// Crypto Data
	f.data = make([]byte, f.Length)
	_, err = r.Read(f.data)
	return r, err
}

// Data returns a copy of the crypto data.
func (f *CRYPTO) Data() []byte {
	return append([]byte{}, f.data...)
}

// This is an old name reserved for compatibility purpose, it is
// equivalent to [QUICFrame].
//
// Deprecated: use the new name [QUICFrame] instead.
type Frame = QUICFrame

// type guards:
var (
	_ QUICFrame = (*PADDING)(nil)
	_ QUICFrame = (*PING)(nil)
	_ QUICFrame = (*CRYPTO)(nil)
)
