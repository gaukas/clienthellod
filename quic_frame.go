package clienthellod

import (
	"fmt"
	"io"

	"github.com/gaukas/clienthellod/internal/utils"
)

const (
	QUICFrame_PADDING uint64 = 0 // 0
	QUICFrame_PING    uint64 = 1 // 1
	QUICFrame_CRYPTO  uint64 = 6 // 6
)

type Frame interface {
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

func ReadAllFrames(r io.Reader) ([]Frame, error) {
	var frames []Frame = make([]Frame, 0)

	for {
		// Frame Type
		frameType, _, err := ReadNextVLI(r)
		if err != nil {
			if err == io.EOF {
				return frames, nil
			}
			return nil, err
		}

		// Frame
		var frame Frame
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
	}
}

// PADDING frame
type PADDING struct {
	Length uint64 `json:"length,omitempty"` // count 0x00 bytes until not 0x00
}

// FrameType implements Frame interface.
func (f *PADDING) FrameType() uint64 {
	return QUICFrame_PADDING
}

// ReadFrom implements Frame interface. It keeps reading until it finds a
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

// FrameType implements Frame interface.
func (f *PING) FrameType() uint64 {
	return QUICFrame_PING
}

// ReadFrom implements Frame interface. It does nothing and returns the
// input reader.
func (f *PING) ReadReader(r io.Reader) (rr io.Reader, err error) {
	return r, nil
}

// CRYPTO frame
type CRYPTO struct {
	Offset uint64 `json:"offset,omitempty"` // offset of crypto data, from VLI
	Length uint64 `json:"length,omitempty"` // length of crypto data, from VLI
	Data   []byte `json:"data,omitempty"`   // crypto data
}

// FrameType implements Frame interface.
func (f *CRYPTO) FrameType() uint64 {
	return QUICFrame_CRYPTO
}

// ReadFrom implements Frame interface. It reads the offset, length and
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
	f.Data = make([]byte, f.Length)
	_, err = r.Read(f.Data)
	return r, err
}
