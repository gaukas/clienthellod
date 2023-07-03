package clienthellod

type ClientInitialPacket struct {
	raw []byte

	QHdr *QUICHeader              `json:"quic_header,omitempty"`               // QUIC header, set by the caller
	CH   *ClientHello             `json:"client_hello,omitempty"`              // TLS ClientHello, set by the caller
	QTP  *QUICTransportParameters `json:"quic_transport_parameters,omitempty"` // QUIC Transport Parameters, set by the caller

	UserAgent string `json:"user_agent,omitempty"` // User-Agent header, set by the caller
}

func ParseQUICCIP(p []byte) (*ClientInitialPacket, error) {
	// TODO: parse QUIC ClientHello, otherwise error
	return &ClientInitialPacket{raw: p}, nil
}
