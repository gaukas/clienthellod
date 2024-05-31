package clienthellod

import (
	"github.com/gaukas/clienthellod/internal/utils"
)

const (
	TOKEN_ABSENT  uint32 = 0x00000000
	TOKEN_PRESENT uint32 = 0x00000001
)

// QUICHeader includes header fields of a QUIC packet and the following
// frames. It is used to calculate the fingerprint of a QUIC Header.
type QUICHeader struct {
	Version                   utils.Uint8Arr `json:"version,omitempty"` // 4-byte version
	DCIDLength                uint32         `json:"dest_conn_id_len,omitempty"`
	SCIDLength                uint32         `json:"source_conn_id_len,omitempty"`
	PacketNumber              utils.Uint8Arr `json:"packet_number,omitempty"` // VLI
	initialPacketNumberLength uint32
	initialPacketNumber       uint64

	HasToken bool `json:"token,omitempty"`
}
