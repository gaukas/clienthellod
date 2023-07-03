package clienthellod

import (
	"reflect"
	"testing"

	"github.com/gaukas/godicttls"
)

var (
	rawQTPExtDataGoogleChrome = []byte{
		0x09, 0x02, 0x40, 0x67, // initial_max_streams_uni
		0x0f, 0x00, // initial_source_connection_id
		0x01, 0x04, 0x80, 0x00, 0x75, 0x30, // max_idle_timeout
		0x05, 0x04, 0x80, 0x60, 0x00, 0x00, // initial_max_stream_data_bidi_local
		0xe2, 0xd0, 0x11, 0x38, 0x87, 0x0c, 0x6f, 0x9f, 0x01, 0x96, // GREASE
		0x07, 0x04, 0x80, 0x60, 0x00, 0x00, // initial_max_stream_data_uni
		0x71, 0x28, 0x04, 0x52, 0x56, 0x43, 0x4d, // google_connection_options
		0x03, 0x02, 0x45, 0xc0, // max_udp_payload_size
		0x20, 0x04, 0x80, 0x01, 0x00, 0x00, // max_datagram_frame_size
		0x08, 0x02, 0x40, 0x64, // initial_max_streams_bidi
		0x80, 0xff, 0x73, 0xdb, 0x0c, 0x00, 0x00, 0x00, 0x01, 0xba, 0xca, 0x5a, 0x5a, 0x00, 0x00, 0x00, 0x01, // version_information
		0x80, 0x00, 0x47, 0x52, 0x04, 0x00, 0x00, 0x00, 0x01, // google_quic_version
		0x06, 0x04, 0x80, 0x60, 0x00, 0x00, // initial_max_stream_data_bidi_remote
		0x04, 0x04, 0x80, 0xf0, 0x00, 0x00, // initial_max_data
	}

	expectedQTPGoogleChrome *QUICTransportParameters = &QUICTransportParameters{
		MaxIdleTimeoutLength:                 4,
		MaxIdleTimeout:                       []byte{0x00, 0x00, 0x75, 0x30},
		MaxUDPPayloadSizeLength:              2,
		MaxUDPPayloadSize:                    []byte{0x05, 0xc0},
		InitialMaxDataLength:                 4,
		InitialMaxData:                       []byte{0x00, 0xf0, 0x00, 0x00},
		InitialMaxStreamDataBidiLocalLength:  4,
		InitialMaxStreamDataBidiLocal:        []byte{0x00, 0x60, 0x00, 0x00},
		InitialMaxStreamDataBidiRemoteLength: 4,
		InitialMaxStreamDataBidiRemote:       []byte{0x00, 0x60, 0x00, 0x00},
		InitialMaxStreamDataUniLength:        4,
		InitialMaxStreamDataUni:              []byte{0x00, 0x60, 0x00, 0x00},
		InitialMaxStreamsBidiLength:          2,
		InitialMaxStreamsBidi:                []byte{0x00, 0x64},
		InitialMaxStreamsUniLength:           2,
		InitialMaxStreamsUni:                 []byte{0x00, 0x67},
		AckDelayExponentLength:               0,
		// AckDelayExponent:                     []byte{}, // nil
		MaxAckDelayLength: 0,
		// MaxAckDelay:                          []byte{}, // nil
		ActiveConnectionIDLimitLength: 0,
		// ActiveConnectionIDLimit:              []byte{}, // nil
		QTPIDs: []uint64{
			godicttls.QUICTransportParameter_max_idle_timeout,
			godicttls.QUICTransportParameter_max_udp_payload_size,
			godicttls.QUICTransportParameter_initial_max_data,
			godicttls.QUICTransportParameter_initial_max_stream_data_bidi_local,
			godicttls.QUICTransportParameter_initial_max_stream_data_bidi_remote,
			godicttls.QUICTransportParameter_initial_max_stream_data_uni,
			godicttls.QUICTransportParameter_initial_max_streams_bidi,
			godicttls.QUICTransportParameter_initial_max_streams_uni,
			godicttls.QUICTransportParameter_initial_source_connection_id,
			QTP_GREASE,
			godicttls.QUICTransportParameter_max_datagram_frame_size,
			godicttls.QUICTransportParameter_google_connection_options,
			godicttls.QUICTransportParameter_google_version,
			0xff73db, // godicttls.QUICTransportParameter_version_information,
		},
		QTPIDSum: 16772298,
	}
)

func TestParseQUICTransportParameters(t *testing.T) {
	t.Run("Google Chrome", parseQUICTransportParametersGoogleChrome)
}

func parseQUICTransportParametersGoogleChrome(t *testing.T) {
	qtp := ParseQUICTransportParameters(rawQTPExtDataGoogleChrome)
	if qtp == nil {
		t.Errorf("ParseQUICTransportParameters failed: got nil")
		return
	}

	if qtp.parseError != nil {
		t.Errorf("ParseQUICTransportParameters failed: %v", qtp.parseError)
		return
	}

	if !reflect.DeepEqual(qtp, expectedQTPGoogleChrome) {
		t.Errorf("ParseQUICTransportParameters failed: expected %v, got %v", expectedQTPGoogleChrome, qtp)
	}
}
