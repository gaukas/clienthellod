package clienthellod_test

import (
	"testing"
	"time"

	. "github.com/gaukas/clienthellod"
)

var mapGatheredClientInitials = map[string][][]byte{
	"Chrome125": {
		quicIETFData_Chrome125_PKN1,
		quicIETFData_Chrome125_PKN2,
	},
	"Firefox126": {
		quicIETFData_Firefox126,
	},
}

func TestGatherClientInitials(t *testing.T) {
	for name, test := range mapGatheredClientInitials {
		t.Run(name, func(t *testing.T) {
			testGatherClientInitials(t, test)
		})
	}
}

func testGatherClientInitials(t *testing.T, data [][]byte) {
	until := time.Now().Add(1 * time.Second) // must be gathered within 1 second

	ci := GatherClientInitialsUntil(until)
	for _, d := range data {
		cip, err := UnmarshalQUICClientInitialPacket(d)
		if err != nil {
			t.Fatal(err)
		}

		err = ci.AddPacket(cip)
		if err != nil {
			t.Fatal(err)
		}
	}

	if !ci.Completed() {
		t.Fatalf("GatheredClientInitials is not completed")
	}
}
