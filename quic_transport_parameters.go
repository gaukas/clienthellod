package clienthellod

import (
	"bytes"
	"errors"
	"io"
	"sort"

	"github.com/gaukas/godicttls"
)

const (
	QTP_GREASE = 27

	UNSET_VLI_BITS = true // if false, unsetVLIBits() will be nop
)

type QUICTransportParameters struct {
	MaxIdleTimeoutLength                 uint32   `json:"max_idle_timeout_len,omitempty"`
	MaxIdleTimeout                       []byte   `json:"max_idle_timeout,omitempty"`
	MaxUDPPayloadSizeLength              uint32   `json:"max_udp_payload_size_len,omitempty"`
	MaxUDPPayloadSize                    []byte   `json:"max_udp_payload_size,omitempty"`
	InitialMaxDataLength                 uint32   `json:"initial_max_data_len,omitempty"`
	InitialMaxData                       []byte   `json:"initial_max_data,omitempty"`
	InitialMaxStreamDataBidiLocalLength  uint32   `json:"initial_max_stream_data_bidi_local_len,omitempty"`
	InitialMaxStreamDataBidiLocal        []byte   `json:"initial_max_stream_data_bidi_local,omitempty"`
	InitialMaxStreamDataBidiRemoteLength uint32   `json:"initial_max_stream_data_bidi_remote_len,omitempty"`
	InitialMaxStreamDataBidiRemote       []byte   `json:"initial_max_stream_data_bidi_remote,omitempty"`
	InitialMaxStreamDataUniLength        uint32   `json:"initial_max_stream_data_uni_len,omitempty"`
	InitialMaxStreamDataUni              []byte   `json:"initial_max_stream_data_uni,omitempty"`
	InitialMaxStreamsBidiLength          uint32   `json:"initial_max_streams_bidi_len,omitempty"`
	InitialMaxStreamsBidi                []byte   `json:"initial_max_streams_bidi,omitempty"`
	InitialMaxStreamsUniLength           uint32   `json:"initial_max_streams_uni_len,omitempty"`
	InitialMaxStreamsUni                 []byte   `json:"initial_max_streams_uni,omitempty"`
	AckDelayExponentLength               uint32   `json:"ack_delay_exponent_len,omitempty"`
	AckDelayExponent                     []byte   `json:"ack_delay_exponent,omitempty"`
	MaxAckDelayLength                    uint32   `json:"max_ack_delay_len,omitempty"`
	MaxAckDelay                          []byte   `json:"max_ack_delay,omitempty"`
	ActiveConnectionIDLimitLength        uint32   `json:"active_connection_id_limit_len,omitempty"`
	ActiveConnectionIDLimit              []byte   `json:"active_connection_id_limit,omitempty"`
	QTPIDs                               []uint64 `json:"qtpid,omitempty"` // sorted
	QTPIDSum                             uint64   `json:"qtpid_sum,omitempty"`

	parseError error
}

func ParseQUICTransportParameters(extData []byte) *QUICTransportParameters {
	qtp := &QUICTransportParameters{
		parseError: errors.New("unknown error"),
	}

	r := bytes.NewReader(extData)
	var paramType uint64
	var paramValLen uint64
	var paramData []byte
	var n int
	for r.Len() > 0 {
		paramType, _, qtp.parseError = ReadNextVLI(r)
		if qtp.parseError != nil {
			return qtp
		}
		paramValLen, _, qtp.parseError = ReadNextVLI(r)
		if qtp.parseError != nil {
			return qtp
		}
		paramData = make([]byte, paramValLen)
		n, qtp.parseError = r.Read(paramData)
		if qtp.parseError != nil {
			return qtp
		}
		if uint64(n) != paramValLen {
			qtp.parseError = errors.New("corrupted transport parameter")
			return qtp
		}

		switch paramType {
		case godicttls.QUICTransportParameter_max_idle_timeout:
			qtp.MaxIdleTimeoutLength = uint32(paramValLen)
			qtp.MaxIdleTimeout = paramData
			unsetVLIBits(qtp.MaxIdleTimeout) // toggle the UNSET_VLI_BITS flag to control behavior
		case godicttls.QUICTransportParameter_max_udp_payload_size:
			qtp.MaxUDPPayloadSizeLength = uint32(paramValLen)
			qtp.MaxUDPPayloadSize = paramData
			unsetVLIBits(qtp.MaxUDPPayloadSize)
		case godicttls.QUICTransportParameter_initial_max_data:
			qtp.InitialMaxDataLength = uint32(paramValLen)
			qtp.InitialMaxData = paramData
			unsetVLIBits(qtp.InitialMaxData)
		case godicttls.QUICTransportParameter_initial_max_stream_data_bidi_local:
			qtp.InitialMaxStreamDataBidiLocalLength = uint32(paramValLen)
			qtp.InitialMaxStreamDataBidiLocal = paramData
			unsetVLIBits(qtp.InitialMaxStreamDataBidiLocal)
		case godicttls.QUICTransportParameter_initial_max_stream_data_bidi_remote:
			qtp.InitialMaxStreamDataBidiRemoteLength = uint32(paramValLen)
			qtp.InitialMaxStreamDataBidiRemote = paramData
			unsetVLIBits(qtp.InitialMaxStreamDataBidiRemote)
		case godicttls.QUICTransportParameter_initial_max_stream_data_uni:
			qtp.InitialMaxStreamDataUniLength = uint32(paramValLen)
			qtp.InitialMaxStreamDataUni = paramData
			unsetVLIBits(qtp.InitialMaxStreamDataUni)
		case godicttls.QUICTransportParameter_initial_max_streams_bidi:
			qtp.InitialMaxStreamsBidiLength = uint32(paramValLen)
			qtp.InitialMaxStreamsBidi = paramData
			unsetVLIBits(qtp.InitialMaxStreamsBidi)
		case godicttls.QUICTransportParameter_initial_max_streams_uni:
			qtp.InitialMaxStreamsUniLength = uint32(paramValLen)
			qtp.InitialMaxStreamsUni = paramData
			unsetVLIBits(qtp.InitialMaxStreamsUni)
		case godicttls.QUICTransportParameter_ack_delay_exponent:
			qtp.AckDelayExponentLength = uint32(paramValLen)
			qtp.AckDelayExponent = paramData
			unsetVLIBits(qtp.AckDelayExponent)
		case godicttls.QUICTransportParameter_max_ack_delay:
			qtp.MaxAckDelayLength = uint32(paramValLen)
			qtp.MaxAckDelay = paramData
			unsetVLIBits(qtp.MaxAckDelay)
		case godicttls.QUICTransportParameter_active_connection_id_limit:
			qtp.ActiveConnectionIDLimitLength = uint32(paramValLen)
			qtp.ActiveConnectionIDLimit = paramData
			unsetVLIBits(qtp.ActiveConnectionIDLimit)
		}

		if IsGREASETransportParameter(paramType) {
			qtp.QTPIDs = append(qtp.QTPIDs, QTP_GREASE)
			qtp.QTPIDSum += QTP_GREASE
		} else {
			qtp.QTPIDs = append(qtp.QTPIDs, paramType)
			qtp.QTPIDSum += paramType
		}
	}

	// sort QTPIDs
	sort.Slice(qtp.QTPIDs, func(i, j int) bool {
		return qtp.QTPIDs[i] < qtp.QTPIDs[j]
	})

	return qtp
}

// ReadNextVLI unpacks the next variable-length integer from the given
// io.Reader. It returns the decoded value and the number of bytes read.
// For example:
//
//	0x0a -> 0xa, 1
//	0x80 0x10 0x00 0x00 -> 0x100000, 4
func ReadNextVLI(r io.Reader) (val uint64, n int, err error) {
	// read the first byte
	var encodedBytes []byte = make([]byte, 1)
	_, err = r.Read(encodedBytes)
	if err != nil {
		return 0, 0, err
	}

	// check MSBs of the first byte
	switch encodedBytes[0] & 0xc0 { // 0xc0 = 0b11000000, when the first 2 bits in a byte is set
	case 0x00:
		n = 1
	case 0x40:
		n = 2
	case 0x80:
		n = 4
	case 0xc0:
		n = 8
	default:
		return 0, 0, errors.New("invalid first byte")
	}

	// read the rest bytes
	if n > 1 {
		encodedBytes = append(encodedBytes, make([]byte, n-1)...)
		_, err = r.Read(encodedBytes[1:])
		if err != nil {
			return 0, 0, err
		}
	}

	// decode
	encodedBytes[0] &= 0x3f // 0x3f = 0b00111111, clear MSBs
	for i := 0; i < n; i++ {
		val <<= 8
		val |= uint64(encodedBytes[i])
	}

	return
}

func DecodeVLI(vli []byte) (val uint64, err error) {
	var n int
	val, n, err = ReadNextVLI(bytes.NewReader(vli))
	if err != nil {
		return 0, err
	}
	if n != len(vli) {
		return 0, errors.New("invalid VLI length")
	}
	return
}

func unsetVLIBits(vli []byte) {
	if UNSET_VLI_BITS {
		vli[0] &= 0x3f // 0x3f = 0b00111111, clear MSBs
	}
}

func IsGREASETransportParameter(paramType uint64) bool {
	return (paramType-27)%31 == 0 // reserved values are 27, 58, 89, ...
}
