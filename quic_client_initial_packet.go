package clienthellod

import (
	"errors"
	"fmt"
)

var ErrNoQUICClientHello = errors.New("no QUIC ClientHello found in the packet")

type ClientInitialPacket struct {
	raw []byte

	QHdr *QUICHeader              `json:"quic_header,omitempty"`               // QUIC header, set by the caller
	QCH  *QUICClientHello         `json:"quic_client_hello,omitempty"`         // TLS ClientHello, set by the caller
	QTP  *QUICTransportParameters `json:"quic_transport_parameters,omitempty"` // QUIC Transport Parameters, set by the caller

	UserAgent string `json:"user_agent,omitempty"` // User-Agent header, set by the caller
}

func ParseQUICCIP(p []byte) (*ClientInitialPacket, error) {
	qHdr, err := DecodeQUICHeaderAndFrames(p)
	if err != nil {
		return nil, err
	}

	cryptoFrame, err := ReassembleCRYPTOFrames(qHdr.frames)
	if err != nil {
		return nil, err
	}

	if len(cryptoFrame) == 0 {
		return nil, fmt.Errorf("%w: no CRYPTO frames found in the packet", ErrNoQUICClientHello)
	}

	ch, err := ParseQUICClientHello(cryptoFrame)
	if err != nil {
		return nil, fmt.Errorf("%w, ParseQUICClientHello(): %v", ErrNoQUICClientHello, err)
	}

	ch.FingerprintID(true)
	ch.FingerprintID(false)

	return &ClientInitialPacket{
		raw:  p,
		QHdr: qHdr,
		QCH:  ch,
		QTP:  ch.qtp,
	}, nil
}
