package clienthellod

import (
	"bytes" // skipcq: GSC-G505
	"errors"
	"fmt"
	"sort"

	"github.com/gaukas/clienthellod/internal/utils"
	"github.com/refraction-networking/utls/dicttls"
)

const (
	QTP_GREASE = 27

	UNSET_VLI_BITS = true // if false, unsetVLIBits() will be nop
)

// QUICTransportParameters is a struct to hold the parsed QUIC transport parameters
// as a combination.
type QUICTransportParameters struct {
	MaxIdleTimeout                 utils.Uint8Arr `json:"max_idle_timeout,omitempty"`
	MaxUDPPayloadSize              utils.Uint8Arr `json:"max_udp_payload_size,omitempty"`
	InitialMaxData                 utils.Uint8Arr `json:"initial_max_data,omitempty"`
	InitialMaxStreamDataBidiLocal  utils.Uint8Arr `json:"initial_max_stream_data_bidi_local,omitempty"`
	InitialMaxStreamDataBidiRemote utils.Uint8Arr `json:"initial_max_stream_data_bidi_remote,omitempty"`
	InitialMaxStreamDataUni        utils.Uint8Arr `json:"initial_max_stream_data_uni,omitempty"`
	InitialMaxStreamsBidi          utils.Uint8Arr `json:"initial_max_streams_bidi,omitempty"`
	InitialMaxStreamsUni           utils.Uint8Arr `json:"initial_max_streams_uni,omitempty"`
	AckDelayExponent               utils.Uint8Arr `json:"ack_delay_exponent,omitempty"`
	MaxAckDelay                    utils.Uint8Arr `json:"max_ack_delay,omitempty"`

	ActiveConnectionIDLimit utils.Uint8Arr `json:"active_connection_id_limit,omitempty"`
	QTPIDs                  []uint64       `json:"tpids,omitempty"` // sorted

	HexID string `json:"hex_id,omitempty"`
	NumID uint64 `json:"num_id,omitempty"`

	parseError error
}

// ParseQUICTransportParameters parses the transport parameters from the extension data of
// TLS Extension "QUIC Transport Parameters" (57)
//
// If any error occurs, the returned struct will have parseError set to the error.
func ParseQUICTransportParameters(extData []byte) *QUICTransportParameters { // skipcq: GO-R1005
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
			qtp.parseError = fmt.Errorf("failed to read transport parameter type: %w", qtp.parseError)
			return qtp
		}
		paramValLen, _, qtp.parseError = ReadNextVLI(r)
		if qtp.parseError != nil {
			qtp.parseError = fmt.Errorf("failed to read transport parameter value length: %w", qtp.parseError)
			return qtp
		}

		if IsGREASETransportParameter(paramType) {
			qtp.QTPIDs = append(qtp.QTPIDs, QTP_GREASE) // replace with placeholder
		} else {
			qtp.QTPIDs = append(qtp.QTPIDs, paramType)
		}

		if paramValLen == 0 {
			continue // skip empty transport parameter, no need to try to read
		}

		paramData = make([]byte, paramValLen)
		n, qtp.parseError = r.Read(paramData)
		if qtp.parseError != nil {
			qtp.parseError = fmt.Errorf("failed to read transport parameter value: %w", qtp.parseError)
			return qtp
		}
		if uint64(n) != paramValLen {
			qtp.parseError = errors.New("corrupted transport parameter")
			return qtp
		}

		switch paramType {
		case dicttls.QUICTransportParameter_max_idle_timeout:
			// qtp.MaxIdleTimeoutLength = uint32(paramValLen)
			qtp.MaxIdleTimeout = paramData
			unsetVLIBits(qtp.MaxIdleTimeout) // toggle the UNSET_VLI_BITS flag to control behavior
		case dicttls.QUICTransportParameter_max_udp_payload_size:
			// qtp.MaxUDPPayloadSizeLength = uint32(paramValLen)
			qtp.MaxUDPPayloadSize = paramData
			unsetVLIBits(qtp.MaxUDPPayloadSize)
		case dicttls.QUICTransportParameter_initial_max_data:
			// qtp.InitialMaxDataLength = uint32(paramValLen)
			qtp.InitialMaxData = paramData
			unsetVLIBits(qtp.InitialMaxData)
		case dicttls.QUICTransportParameter_initial_max_stream_data_bidi_local:
			// qtp.InitialMaxStreamDataBidiLocalLength = uint32(paramValLen)
			qtp.InitialMaxStreamDataBidiLocal = paramData
			unsetVLIBits(qtp.InitialMaxStreamDataBidiLocal)
		case dicttls.QUICTransportParameter_initial_max_stream_data_bidi_remote:
			// qtp.InitialMaxStreamDataBidiRemoteLength = uint32(paramValLen)
			qtp.InitialMaxStreamDataBidiRemote = paramData
			unsetVLIBits(qtp.InitialMaxStreamDataBidiRemote)
		case dicttls.QUICTransportParameter_initial_max_stream_data_uni:
			// qtp.InitialMaxStreamDataUniLength = uint32(paramValLen)
			qtp.InitialMaxStreamDataUni = paramData
			unsetVLIBits(qtp.InitialMaxStreamDataUni)
		case dicttls.QUICTransportParameter_initial_max_streams_bidi:
			// qtp.InitialMaxStreamsBidiLength = uint32(paramValLen)
			qtp.InitialMaxStreamsBidi = paramData
			unsetVLIBits(qtp.InitialMaxStreamsBidi)
		case dicttls.QUICTransportParameter_initial_max_streams_uni:
			// qtp.InitialMaxStreamsUniLength = uint32(paramValLen)
			qtp.InitialMaxStreamsUni = paramData
			unsetVLIBits(qtp.InitialMaxStreamsUni)
		case dicttls.QUICTransportParameter_ack_delay_exponent:
			// qtp.AckDelayExponentLength = uint32(paramValLen)
			qtp.AckDelayExponent = paramData
			unsetVLIBits(qtp.AckDelayExponent)
		case dicttls.QUICTransportParameter_max_ack_delay:
			// qtp.MaxAckDelayLength = uint32(paramValLen)
			qtp.MaxAckDelay = paramData
			unsetVLIBits(qtp.MaxAckDelay)
		case dicttls.QUICTransportParameter_active_connection_id_limit:
			// qtp.ActiveConnectionIDLimitLength = uint32(paramValLen)
			qtp.ActiveConnectionIDLimit = paramData
			unsetVLIBits(qtp.ActiveConnectionIDLimit)
		}

		// if IsGREASETransportParameter(paramType) {
		// 	qtp.QTPIDs = append(qtp.QTPIDs, QTP_GREASE) // replace with placeholder
		// } else {
		// 	qtp.QTPIDs = append(qtp.QTPIDs, paramType)
		// }
	}

	// sort QTPIDs
	sort.Slice(qtp.QTPIDs, func(i, j int) bool {
		return qtp.QTPIDs[i] < qtp.QTPIDs[j]
	})

	qtp.parseError = nil
	qtp.NumID = qtp.calcNumericID()
	qtp.HexID = FingerprintID(qtp.NumID).AsHex()
	return qtp
}

// ParseError returns the error that occurred during parsing, if any.
func (qtp *QUICTransportParameters) ParseError() error {
	return qtp.parseError
}
