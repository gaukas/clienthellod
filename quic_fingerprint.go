package clienthellod

import (
	"crypto/sha1" // skipcq: GSC-G505
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaukas/clienthellod/internal/utils"
)

type QUICFingerprint struct {
	ClientInitials *GatheredClientInitials

	HexID string `json:"hex_id,omitempty"`
	NumID uint64 `json:"num_id,omitempty"`

	UserAgent string `json:"user_agent,omitempty"` // User-Agent header, set by the caller
}

func GenerateQUICFingerprint(gci *GatheredClientInitials, userAgent string) (*QUICFingerprint, error) {
	if err := gci.Wait(); err != nil {
		return nil, err // GatheringClientInitials failed (expired before complete)
	}

	qfp := &QUICFingerprint{
		ClientInitials: gci,
		UserAgent:      userAgent,
	}

	// TODO: calculate hash
	h := sha1.New() // skipcq: GO-S1025, GSC-G401
	updateU64(h, gci.NumID)
	updateU64(h, uint64(gci.ClientHello.NumID))
	updateU64(h, gci.TransportParameters.NumID)

	qfp.NumID = binary.BigEndian.Uint64(h.Sum(nil))
	qfp.HexID = FingerprintID(qfp.NumID).AsHex()

	return qfp, nil
}

type QUICFingerprinter struct {
	mapGatheringClientInitials *sync.Map

	timeout time.Duration
	closed  atomic.Bool
}

func NewQUICFingerprinter() *QUICFingerprinter {
	return &QUICFingerprinter{
		mapGatheringClientInitials: new(sync.Map),
		closed:                     atomic.Bool{},
	}
}

func (fgp *QUICFingerprinter) HandlePacket(from string, p []byte) error {
	ci, err := UnmarshalQUICClientInitialPacket(p)
	if err != nil {
		if errors.Is(err, ErrNotQUICLongHeaderFormat) || errors.Is(err, ErrNotQUICInitialPacket) {
			return nil // totally fine, we don't care about non QUIC initials
		}
		return err
	}

	var testGci *GatheredClientInitials
	if fgp.timeout == time.Duration(0) {
		testGci = GatherClientInitials()
	} else {
		testGci = GatherClientInitialsUntil(time.Now().Add(fgp.timeout))
	}

	chosenGci, existing := fgp.mapGatheringClientInitials.LoadOrStore(from, testGci)
	if !existing {
		// if we stored the testGci, we need to remember to delete it after the timeout
		go func() {
			<-time.After(fgp.timeout)
			fgp.mapGatheringClientInitials.Delete(from)
		}()
	}

	gci, ok := chosenGci.(*GatheredClientInitials)
	if !ok {
		return errors.New("GatheredClientInitials loaded from sync.Map failed type assertion")
	}

	return gci.AddPacket(ci)
}

func (fgp *QUICFingerprinter) HandleUDPConn(pc net.PacketConn) error {
	var buf [2048]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return err
			}
			continue // ignore errors unless connection is closed
		}

		fgp.HandlePacket(addr.String(), buf[:n])
	}
}

func (fgp *QUICFingerprinter) HandleIPConn(ipc *net.IPConn) error {
	var buf [2048]byte
	for {
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

		fgp.HandlePacket(udpAddr.String(), udpPkt.Payload)
	}
}

func (fgp *QUICFingerprinter) Lookup(from string) *QUICFingerprint {
	gci, ok := fgp.mapGatheringClientInitials.Load(from)
	if !ok {
		return nil
	}

	gatheredCI, ok := gci.(*GatheredClientInitials)
	if !ok {
		return nil
	}

	if !gatheredCI.Completed() {
		return nil
	}

	qfp, err := GenerateQUICFingerprint(gatheredCI, "")
	if err != nil {
		return nil
	}

	return qfp
}

func (fgp *QUICFingerprinter) LookupAwait(from string) (*QUICFingerprint, error) {
	gci, ok := fgp.mapGatheringClientInitials.Load(from)
	if !ok {
		return nil, errors.New("GatheredClientInitials not found for the given key")
	}

	gatheredCI, ok := gci.(*GatheredClientInitials)
	if !ok {
		return nil, errors.New("GatheredClientInitials loaded from sync.Map failed type assertion")
	}

	qfp, err := GenerateQUICFingerprint(gatheredCI, "")
	if err != nil {
		return nil, err
	}

	return qfp, nil
}
