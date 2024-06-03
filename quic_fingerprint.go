package clienthellod

import (
	"crypto/sha1" // skipcq: GSC-G505
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaukas/clienthellod/internal/utils"
)

// QUICFingerprint can be used to generate a fingerprint of a QUIC connection.
type QUICFingerprint struct {
	ClientInitials *GatheredClientInitials

	HexID string `json:"hex_id,omitempty"`
	NumID uint64 `json:"num_id,omitempty"`

	UserAgent string `json:"user_agent,omitempty"` // User-Agent header, set by the caller
}

// GenerateQUICFingerprint generates a QUICFingerprint from the gathered ClientInitials.
func GenerateQUICFingerprint(gci *GatheredClientInitials) (*QUICFingerprint, error) {
	if err := gci.Wait(); err != nil {
		return nil, err // GatheringClientInitials failed (expired before complete)
	}

	qfp := &QUICFingerprint{
		ClientInitials: gci,
		// UserAgent:      userAgent,
	}

	// TODO: calculate hash
	h := sha1.New() // skipcq: GO-S1025, GSC-G401
	updateU64(h, gci.NumID)
	updateU64(h, uint64(gci.ClientHello.NormNumID))
	updateU64(h, gci.TransportParameters.NumID)

	qfp.NumID = binary.BigEndian.Uint64(h.Sum(nil))
	qfp.HexID = FingerprintID(qfp.NumID).AsHex()

	runtime.SetFinalizer(qfp, func(q *QUICFingerprint) {
		q.ClientInitials = nil
	})

	return qfp, nil
}

const DEFAULT_QUICFINGERPRINT_EXPIRY = 10 * time.Second

// QUICFingerprinter can be used to fingerprint QUIC connections.
type QUICFingerprinter struct {
	mapGatheringClientInitials *sync.Map

	timeout time.Duration
	closed  atomic.Bool
}

// NewQUICFingerprinter creates a new QUICFingerprinter.
func NewQUICFingerprinter() *QUICFingerprinter {
	return &QUICFingerprinter{
		mapGatheringClientInitials: new(sync.Map),
		closed:                     atomic.Bool{},
	}
}

// NewQUICFingerprinterWithTimeout creates a new QUICFingerprinter with a timeout.
func NewQUICFingerprinterWithTimeout(timeout time.Duration) *QUICFingerprinter {
	return &QUICFingerprinter{
		mapGatheringClientInitials: new(sync.Map),
		timeout:                    timeout,
		closed:                     atomic.Bool{},
	}
}

// SetTimeout sets the timeout for gathering ClientInitials.
func (qfp *QUICFingerprinter) SetTimeout(timeout time.Duration) {
	qfp.timeout = timeout
}

// HandlePacket handles a QUIC packet.
func (qfp *QUICFingerprinter) HandlePacket(from string, p []byte) error {
	if qfp.closed.Load() {
		return errors.New("QUICFingerprinter closed")
	}

	ci, err := UnmarshalQUICClientInitialPacket(p)
	if err != nil {
		if errors.Is(err, ErrNotQUICLongHeaderFormat) || errors.Is(err, ErrNotQUICInitialPacket) {
			return nil // totally fine, we don't care about non QUIC initials
		}
		return err
	}

	var testGci *GatheredClientInitials
	if qfp.timeout == time.Duration(0) {
		testGci = GatherClientInitials()
	} else {
		testGci = GatherClientInitialsWithDeadline(time.Now().Add(qfp.timeout))
	}

	chosenGci, existing := qfp.mapGatheringClientInitials.LoadOrStore(from, testGci)
	if !existing {
		// if we stored the testGci, we need to delete it after the timeout
		funcExpiringAfter := func(d time.Duration) {
			<-time.After(d)
			qfp.mapGatheringClientInitials.Delete(from)
		}

		if qfp.timeout == time.Duration(0) {
			go funcExpiringAfter(DEFAULT_QUICFINGERPRINT_EXPIRY)
		} else {
			go funcExpiringAfter(qfp.timeout)
		}
	}

	gci, ok := chosenGci.(*GatheredClientInitials)
	if !ok {
		return errors.New("GatheredClientInitials loaded from sync.Map failed type assertion")
	}

	return gci.AddPacket(ci)
}

// HandleUDPConn handles a QUIC connection over UDP.
func (qfp *QUICFingerprinter) HandleUDPConn(pc net.PacketConn) error {
	var buf [2048]byte
	for {
		if qfp.closed.Load() {
			return errors.New("QUICFingerprinter closed")
		}

		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return err
			}
			continue // ignore errors unless connection is closed
		}

		qfp.HandlePacket(addr.String(), buf[:n])
	}
}

// HandleIPConn handles a QUIC connection over IP.
func (qfp *QUICFingerprinter) HandleIPConn(ipc *net.IPConn) error {
	var buf [2048]byte
	for {
		if qfp.closed.Load() {
			return errors.New("QUICFingerprinter closed")
		}

		n, ipAddr, err := ipc.ReadFromIP(buf[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return err
			}
			continue // ignore errors unless connection is closed
		}

		udpPkt, err := utils.ParseUDPPacket(buf[:n])
		if err != nil {
			continue
		}
		if udpPkt.DstPort != 443 {
			continue
		}
		udpAddr := &net.UDPAddr{IP: ipAddr.IP, Port: int(udpPkt.SrcPort)}

		qfp.HandlePacket(udpAddr.String(), udpPkt.Payload)
	}
}

// Lookup looks up a QUICFingerprint for a given key.
func (qfp *QUICFingerprinter) Lookup(from string) *QUICFingerprint {
	gci, ok := qfp.mapGatheringClientInitials.Load(from) // when using LoadAndDelete, some implementations "wasting" QUIC connections will fail
	if !ok {
		return nil
	}

	gatheredCI, ok := gci.(*GatheredClientInitials)
	if !ok {
		return nil
	}

	if !gatheredCI.Completed() {
		return nil // gathering incomplete
	}

	qf, err := GenerateQUICFingerprint(gatheredCI)
	if err != nil {
		return nil
	}

	return qf
}

// LookupAwait looks up a QUICFingerprint for a given key, waiting for the gathering to complete.
func (qfp *QUICFingerprinter) LookupAwait(from string) (*QUICFingerprint, error) {
	gci, ok := qfp.mapGatheringClientInitials.Load(from) // when using LoadAndDelete, some implementations "wasting" QUIC connections will fail
	if !ok {
		return nil, errors.New("GatheredClientInitials not found for the given key")
	}

	gatheredCI, ok := gci.(*GatheredClientInitials)
	if !ok {
		return nil, errors.New("GatheredClientInitials loaded from sync.Map failed type assertion")
	}

	qf, err := GenerateQUICFingerprint(gatheredCI)
	if err != nil {
		return nil, err
	}

	return qf, nil
}

// Close closes the QUICFingerprinter.
func (qfp *QUICFingerprinter) Close() {
	qfp.closed.Store(true)
}
