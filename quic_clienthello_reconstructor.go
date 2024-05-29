package clienthellod

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type QUICClientHelloReconstructor struct {
	fullLen uint32 // parse from first fragment
	buf     []byte

	frags map[uint64][]byte // offset: fragment, pending to be parsed
}

func NewQUICClientHelloReconstructor() *QUICClientHelloReconstructor {
	return &QUICClientHelloReconstructor{
		frags: make(map[uint64][]byte),
	}
}

var (
	ErrDuplicateFragment = errors.New("duplicate CRYPTO frame detected")
	ErrOverlapFragment   = errors.New("overlap CRYPTO frame detected")
	ErrTooManyFragments  = errors.New("too many CRYPTO fragments")
	ErrOffsetTooHigh     = errors.New("offset too high")
	ErrNeedMoreFrames    = errors.New("need more CRYPTO frames")
)

const maxCRYPTOFragments = 32
const maxCRYPTOLength = 0x10000 // 10KiB

// AddCRYPTOFragment adds a CRYPTO frame fragment to the reconstructor.
// By default, all fragments are saved into an internal map as a pending
// fragment, UNLESS all fragments before it have been reassembled.
// If the fragment is the last one, it will return io.EOF.
func (qchr *QUICClientHelloReconstructor) AddCRYPTOFragment(offset uint64, frag []byte) error {
	// Check for duplicate. The new fragment should not be a duplicate
	// of any pending-reassemble fragments.
	if _, ok := qchr.frags[offset]; ok {
		return ErrDuplicateFragment
	}

	// Check for overlap. For all pending-reassemble fragments, none of them
	// should overlap with the new fragment.
	for off, f := range qchr.frags {
		if (off < offset && off+uint64(len(f)) > offset) || (offset < off && offset+uint64(len(frag)) > off) {
			return ErrOverlapFragment
		}
	}

	// The newly added fragment should not overlap with the already-reassembled
	// buffer.
	if offset < uint64(len(qchr.buf)) {
		return ErrOverlapFragment
	}

	// Check for pending fragments count
	if len(qchr.frags) > maxCRYPTOFragments {
		return ErrTooManyFragments
	}

	// Check for offset and length: must not be exceeding
	// the maximum length of a CRYPTO frame.
	if offset+uint64(len(frag)) > maxCRYPTOLength {
		// log.Printf("offset too high: %d + %d > %d", offset, len(frag), maxCRYPTOLength)
		return ErrOffsetTooHigh
	}

	// Save fragment
	qchr.frags[offset] = frag

	for {
		// assemble next available fragment until no more
		if f, ok := qchr.frags[uint64(len(qchr.buf))]; ok {
			copyF := make([]byte, len(f))
			copy(copyF, f)
			delete(qchr.frags, uint64(len(qchr.buf)))
			qchr.buf = append(qchr.buf, copyF...)
		} else {
			break
		}
	}

	// If fullLeh is yet to be determined and we expect to have
	// enough bytes to parse the full length, then parse it.
	if qchr.fullLen == 0 {
		if len(qchr.buf) > 4 {
			qchr.fullLen = binary.BigEndian.Uint32([]byte{
				0x0, qchr.buf[1], qchr.buf[2], qchr.buf[3],
			}) + 4 // Handshake Type (1) + uint24 Length (3) + ClientHello body

			if qchr.fullLen > maxCRYPTOLength {
				// log.Printf("offset too high: %d > %d", qchr.fullLen, maxCRYPTOLength)
				return ErrOffsetTooHigh
			}
		}
	}

	if qchr.fullLen > 0 && uint32(len(qchr.buf)) >= qchr.fullLen { // if we have at least the full length bytes of data, we conclude the CRYPTO frame is complete
		// log.Printf("fullLen: %d, buf: %d, completed!", qchr.fullLen, len(qchr.buf))
		// log.Printf("First 4 bytes from buf: %x", qchr.buf[:4])
		return io.EOF // io.EOF means no more fragments expected
	}

	return nil
}

func (qchr *QUICClientHelloReconstructor) ReconstructAsBytes() []byte {
	if qchr.fullLen == 0 {
		return nil
	} else if uint32(len(qchr.buf)) < qchr.fullLen {
		return nil
	} else {
		return qchr.buf
	}
}

func (qchr *QUICClientHelloReconstructor) Reconstruct() (*QUICClientHello, error) {
	if b := qchr.ReconstructAsBytes(); len(b) > 0 {
		return ParseQUICClientHello(b)
	}

	return nil, ErrNeedMoreFrames
}

// FromFrames reassembles the ClientHello from the CRYPTO frames
func (qr *QUICClientHelloReconstructor) FromFrames(frames []Frame) error {
	// Collect all CRYPTO frames
	for _, frame := range frames {
		if frame.FrameType() == QUICFrame_CRYPTO {
			switch c := frame.(type) {
			case *CRYPTO:
				if err := qr.AddCRYPTOFragment(c.Offset, c.data); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					} else {
						return err
					}
				}
			default:
				return fmt.Errorf("unknown CRYPTO frame type %T", c)
			}
		}
	}

	return ErrNeedMoreFrames
}
