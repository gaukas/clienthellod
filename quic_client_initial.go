package clienthellod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// skipcq: GSC-G505

type ClientInitial struct {
	Header *QUICHeader `json:"header,omitempty"` // QUIC header
	Frames []uint64    `json:"frames,omitempty"` // frames ID in order
	frames QUICFrames  // frames in order
	raw    []byte
}

// UnmarshalQUICClientInitialPacket is similar to ParseQUICCIP, but on error
// such as ClientHello cannot be parsed, it returns a partially completed
// ClientInitialPacket instead of nil.
func UnmarshalQUICClientInitialPacket(p []byte) (ci *ClientInitial, err error) {
	ci = &ClientInitial{
		raw: p,
	}

	ci.Header, ci.frames, err = DecodeQUICHeaderAndFrames(p)
	if err != nil {
		return
	}

	ci.Frames = ci.frames.FrameTypes()

	// reassembledCRYPTOFrame, err := ReassembleCRYPTOFrames(cip.Header.Frames())
	// if err != nil {
	// 	return cip, err
	// }

	// if len(reassembledCRYPTOFrame) == 0 {
	// 	return cip, fmt.Errorf("%w: no CRYPTO frames found in the packet", ErrNoQUICClientHello)
	// }

	// cip.QCH, err = ParseQUICClientHello(reassembledCRYPTOFrame)
	// if err != nil {
	// 	return cip, fmt.Errorf("%w, ParseQUICClientHello(): %v", ErrNoQUICClientHello, err)
	// }
	// cip.QCH.FingerprintID(true)  // normalized
	// cip.QCH.FingerprintID(false) // original
	// if cip.QCH.qtp != nil {
	// 	cip.QTP = cip.QCH.qtp
	// 	cip.QCH.qtp.HID()
	// } else {
	// 	return cip, fmt.Errorf("%w: no QUIC Transport Parameters found in the packet", ErrNoQUICClientHello)
	// }

	// // Calculate fp
	// h := sha1.New() // skipcq: GO-S1025, GSC-G401
	// updateU64(h, cip.QHdr.NID())
	// updateU64(h, uint64(cip.QCH.FingerprintNID(true)))
	// updateU64(h, cip.QTP.NumericID)
	// cip.NumericID = binary.BigEndian.Uint64(h.Sum(nil))
	// hid := make([]byte, 8)
	// binary.BigEndian.PutUint64(hid, cip.NumericID)
	// cip.HexID = hex.EncodeToString(hid)

	return ci, nil
}

// GatheredClientInitials represents a series of Initial Packets sent by the Client to initiate
// the QUIC handshake.
type GatheredClientInitials struct {
	Packets   []*ClientInitial `json:"packets,omitempty"` // sorted by ClientInitial.PacketNumber
	pktsMutex *sync.Mutex

	clientHelloReconstructor *QUICClientHelloReconstructor
	ClientHello              *QUICClientHello         `json:"client_hello,omitempty"`         // TLS ClientHello
	TransportParameters      *QUICTransportParameters `json:"transport_parameters,omitempty"` // QUIC Transport Parameters extracted from the extension in ClientHello

	HexID string `json:"hex_id,omitempty"`
	NumID uint64 `json:"num_id,omitempty"`

	expiringCtx       context.Context
	cancelExpiringCtx context.CancelFunc
	completed         atomic.Bool
}

// GatherClientInitialPackets reads a series of Client Initial Packets from the input channel
// and returns the result of the gathered packets.
func GatherClientInitials() *GatheredClientInitials {
	return &GatheredClientInitials{
		Packets:                  make([]*ClientInitial, 0, 4), // expecting 4 packets at max
		pktsMutex:                &sync.Mutex{},
		clientHelloReconstructor: NewQUICClientHelloReconstructor(),
		expiringCtx:              context.Background(), // by default, never expire
		cancelExpiringCtx:        func() {},
	}
}

func GatherClientInitialsUntil(expiry time.Time) *GatheredClientInitials {
	gci := GatherClientInitials()
	gci.expiringCtx, gci.cancelExpiringCtx = context.WithDeadline(context.Background(), expiry)
	return gci
}

func (gci *GatheredClientInitials) AddPacket(cip *ClientInitial) error {
	gci.pktsMutex.Lock()
	defer gci.pktsMutex.Unlock()

	if gci.Expired() { // not allowing new packets after expiry
		return errors.New("ClientInitials gathering has expired")
	}

	if gci.ClientHello != nil { // parse complete, new packet likely to be an ACK-only frame, ignore
		return nil
	}

	// check if duplicate packet number was received, if so, discard
	for _, p := range gci.Packets {
		if p.Header.initialPacketNumber == cip.Header.initialPacketNumber {
			return nil
		}
	}

	gci.Packets = append(gci.Packets, cip)

	// sort by initialPacketNumber
	sort.Slice(gci.Packets, func(i, j int) bool {
		return gci.Packets[i].Header.initialPacketNumber < gci.Packets[j].Header.initialPacketNumber
	})

	if err := gci.clientHelloReconstructor.FromFrames(cip.frames); err != nil {
		if errors.Is(err, ErrNeedMoreFrames) {
			return nil // abort early, need more frames before ClientHello can be reconstructed
		} else {
			return fmt.Errorf("failed to reassemble ClientHello: %w", err)
		}
	}

	return gci.lockedGatherComplete()
}

func (gci *GatheredClientInitials) Expired() bool {
	return gci.expiringCtx.Err() != nil
}

func (gci *GatheredClientInitials) lockedGatherComplete() error {
	var err error
	// First, reconstruct the ClientHello
	gci.ClientHello, err = gci.clientHelloReconstructor.Reconstruct()
	if err != nil {
		return fmt.Errorf("failed to reconstruct ClientHello: %w", err)
	}

	// Next, point the TransportParameters to the ClientHello's qtp
	gci.TransportParameters = gci.ClientHello.qtp

	// Then calculate the NumericID
	numericID := gci.calcNumericID()
	atomic.StoreUint64(&gci.NumID, numericID)
	gci.HexID = FingerprintID(numericID).AsHex()

	// cancel the expiry context if any
	gci.cancelExpiringCtx()

	// Finally, mark the completion
	gci.completed.Store(true)

	b, err := json.Marshal(gci)
	if err != nil {
		return err
	}
	log.Printf("GatheredClientInitials: %s", string(b))

	return nil
}

// Wait blocks until the GatheredClientInitials is complete or expired.
func (gci *GatheredClientInitials) Wait() error {
	if gci.completed.Load() {
		return nil
	}

	for {
		if gci.completed.Load() {
			return nil
		}

		select {
		case <-gci.expiringCtx.Done():
			return gci.expiringCtx.Err()
		default:
			time.Sleep(1 * time.Millisecond) // TODO: 1ms is far longer than the processing time but far shorter than the RTT, thus a reasonable sleep duration
		}
	}
}

func (gci *GatheredClientInitials) Completed() bool {
	return gci.completed.Load()
}
