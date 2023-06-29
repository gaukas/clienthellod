package clienthellod

type QClientHello struct {
	raw []byte

	UserAgent string `json:"user_agent,omitempty"` // User-Agent header, set by the caller
}

func ParseQClientHello(p []byte) (*QClientHello, error) {
	// TODO: parse QUIC ClientHello, otherwise error
	return &QClientHello{raw: p}, nil
}

func (*QClientHello) FingerprintID(_ bool) string {
	return "DEADBEEFBAADCAFE"
}

func (*QClientHello) FingerprintNID(_ bool) int64 {
	return 0
}

func (*QClientHello) ParseClientHello() error {
	return nil
}

func (qch *QClientHello) Raw() []byte {
	return qch.raw
}

func (*QClientHello) parseExtra() error {
	return nil
}
