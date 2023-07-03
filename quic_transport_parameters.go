package clienthellod

import (
	"bytes"
	"errors"
	"sort"

	"github.com/gaukas/clienthellod/internal/utils"
	"github.com/gaukas/godicttls"
)

const (
	QTP_GREASE = 27

	UNSET_VLI_BITS = true // if false, unsetVLIBits() will be nop
)

type QUICTransportParameters struct {
	MaxIdleTimeoutLength                 uint32         `json:"max_idle_timeout_len,omitempty"`
	MaxIdleTimeout                       utils.Uint8Arr `json:"max_idle_timeout,omitempty"`
	MaxUDPPayloadSizeLength              uint32         `json:"max_udp_payload_size_len,omitempty"`
	MaxUDPPayloadSize                    utils.Uint8Arr `json:"max_udp_payload_size,omitempty"`
	InitialMaxDataLength                 uint32         `json:"initial_max_data_len,omitempty"`
	InitialMaxData                       utils.Uint8Arr `json:"initial_max_data,omitempty"`
	InitialMaxStreamDataBidiLocalLength  uint32         `json:"initial_max_stream_data_bidi_local_len,omitempty"`
	InitialMaxStreamDataBidiLocal        utils.Uint8Arr `json:"initial_max_stream_data_bidi_local,omitempty"`
	InitialMaxStreamDataBidiRemoteLength uint32         `json:"initial_max_stream_data_bidi_remote_len,omitempty"`
	InitialMaxStreamDataBidiRemote       utils.Uint8Arr `json:"initial_max_stream_data_bidi_remote,omitempty"`
	InitialMaxStreamDataUniLength        uint32         `json:"initial_max_stream_data_uni_len,omitempty"`
	InitialMaxStreamDataUni              utils.Uint8Arr `json:"initial_max_stream_data_uni,omitempty"`
	InitialMaxStreamsBidiLength          uint32         `json:"initial_max_streams_bidi_len,omitempty"`
	InitialMaxStreamsBidi                utils.Uint8Arr `json:"initial_max_streams_bidi,omitempty"`
	InitialMaxStreamsUniLength           uint32         `json:"initial_max_streams_uni_len,omitempty"`
	InitialMaxStreamsUni                 utils.Uint8Arr `json:"initial_max_streams_uni,omitempty"`
	AckDelayExponentLength               uint32         `json:"ack_delay_exponent_len,omitempty"`
	AckDelayExponent                     utils.Uint8Arr `json:"ack_delay_exponent,omitempty"`
	MaxAckDelayLength                    uint32         `json:"max_ack_delay_len,omitempty"`
	MaxAckDelay                          utils.Uint8Arr `json:"max_ack_delay,omitempty"`
	ActiveConnectionIDLimitLength        uint32         `json:"active_connection_id_limit_len,omitempty"`
	ActiveConnectionIDLimit              utils.Uint8Arr `json:"active_connection_id_limit,omitempty"`
	QTPIDs                               []uint64       `json:"qtpid,omitempty"` // sorted
	QTPIDSum                             uint64         `json:"qtpid_sum,omitempty"`

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

	qtp.parseError = nil
	return qtp
}
