package clienthellod

type QUICHeader struct {
	InitialPacketNumberLength uint32 `json:"pn_len,omitempty"`  // TODO: from Packet Header Byte, +1 or not?
	VersionLength             uint32 `json:"ver_len,omitempty"` // TODO: is it not fixed 4-byte?
	Version                   []byte `json:"version,omitempty"` // 4-byte version
	DCIDLength                uint32 `json:"dcid_len,omitempty"`
	SCIDLength                uint32 `json:"scid_len,omitempty"`
	TokenLength               uint32 `json:"token_len,omitempty"`
	InitialPacketNumber       uint32 `json:"pn,omitempty"` // TODO: protected or unprotected?

	// These two fields are not strictly part of QUIC header, but we need them before parsing QUIC ClientHello
	FramesPresentLength uint32   `json:"frames_present_len,omitempty"` // TODO: length of all frames OR number of frames?
	FrameIDs            []uint32 `json:"frame_id,omitempty"`           // sorted
	Frames              []Frame  `json:"frames,omitempty"`             // sorted
}
