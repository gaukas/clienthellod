package clienthellod_test

import (
	"bytes"
	"testing"

	. "github.com/gaukas/clienthellod"
)

// TODO: update test data to the latest and move test data to separate files (in binary format)

var (
	quicHeaderTruth_Chrome125_PKN1 = &QUICHeader{
		Version:      []byte{0x00, 0x00, 0x00, 0x01},
		DCIDLength:   8,
		SCIDLength:   0,
		PacketNumber: []byte{0x01},

		HasToken: false,
	}
	quicHeaderTruth_Chrome125_PKN2 = &QUICHeader{
		Version:      []byte{0x00, 0x00, 0x00, 0x01},
		DCIDLength:   8,
		SCIDLength:   0,
		PacketNumber: []byte{0x02},

		HasToken: false,
	}

	quicHeaderTruth_Firefox126 = &QUICHeader{
		Version:      []byte{0x00, 0x00, 0x00, 0x01},
		DCIDLength:   8,
		SCIDLength:   3,
		PacketNumber: []byte{0x00},

		HasToken: false,
	}
)

func testQUICHeaderEqualsTruth(t *testing.T, header, truth *QUICHeader) {
	if !bytes.Equal(header.Version, truth.Version) {
		t.Errorf("header.Version = %x, want %x", header.Version, truth.Version)
	}

	if header.DCIDLength != truth.DCIDLength {
		t.Errorf("header.DCIDLength = %d, want %d", header.DCIDLength, truth.DCIDLength)
	}

	if header.SCIDLength != truth.SCIDLength {
		t.Errorf("header.SCIDLength = %d, want %d", header.SCIDLength, truth.SCIDLength)
	}

	if !bytes.Equal(header.PacketNumber, truth.PacketNumber) {
		t.Errorf("header.PacketNumber = %x, want %x", header.PacketNumber, truth.PacketNumber)
	}

	if header.HasToken != truth.HasToken {
		t.Errorf("header.HasToken = %t, want %t", header.HasToken, truth.HasToken)
	}
}
