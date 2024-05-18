package clienthellod

import (
	"reflect"
	"testing"

	"github.com/refraction-networking/utls/dicttls"
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
		MaxIdleTimeout:                 []byte{0x00, 0x00, 0x75, 0x30},
		MaxUDPPayloadSize:              []byte{0x05, 0xc0},
		InitialMaxData:                 []byte{0x00, 0xf0, 0x00, 0x00},
		InitialMaxStreamDataBidiLocal:  []byte{0x00, 0x60, 0x00, 0x00},
		InitialMaxStreamDataBidiRemote: []byte{0x00, 0x60, 0x00, 0x00},
		InitialMaxStreamDataUni:        []byte{0x00, 0x60, 0x00, 0x00},
		InitialMaxStreamsBidi:          []byte{0x00, 0x64},
		InitialMaxStreamsUni:           []byte{0x00, 0x67},
		// AckDelayExponent:                     []byte{}, // nil
		// MaxAckDelay:                          []byte{}, // nil
		// ActiveConnectionIDLimit:              []byte{}, // nil
		QTPIDs: []uint64{
			dicttls.QUICTransportParameter_max_idle_timeout,
			dicttls.QUICTransportParameter_max_udp_payload_size,
			dicttls.QUICTransportParameter_initial_max_data,
			dicttls.QUICTransportParameter_initial_max_stream_data_bidi_local,
			dicttls.QUICTransportParameter_initial_max_stream_data_bidi_remote,
			dicttls.QUICTransportParameter_initial_max_stream_data_uni,
			dicttls.QUICTransportParameter_initial_max_streams_bidi,
			dicttls.QUICTransportParameter_initial_max_streams_uni,
			dicttls.QUICTransportParameter_initial_source_connection_id,
			QTP_GREASE,
			dicttls.QUICTransportParameter_max_datagram_frame_size,
			dicttls.QUICTransportParameter_google_connection_options,
			dicttls.QUICTransportParameter_google_version,
			0xff73db, // dicttls.QUICTransportParameter_version_information,
		},
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
