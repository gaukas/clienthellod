package clienthellod_test

import (
	"runtime"
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
	"Firefox126_0-RTT": {
		quicIETFData_Firefox126_0_RTT,
	},
}

func TestGatherClientInitials(t *testing.T) {
	for name, test := range mapGatheredClientInitials {
		t.Run(name, func(t *testing.T) {
			testGatherClientInitialsWithRawPayload(t, test)
		})
	}
}

func testGatherClientInitialsWithRawPayload(t *testing.T, data [][]byte) {
	until := time.Now().Add(1 * time.Second) // must be gathered within 1 second

	ci := GatherClientInitialsWithDeadline(until)
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

func TestGatheredClientInitialsGC(t *testing.T) {
	gcOk := make(chan bool, 1)
	gci := GatherClientInitials()

	// Use a dummy ClientHello to detect if the GatheredClientInitials is GCed
	dummyClientHello := &QUICClientHello{}
	gci.ClientHello = dummyClientHello
	runtime.SetFinalizer(dummyClientHello, func(c *QUICClientHello) {
		close(gcOk)
	})

	gcCnt := 0
	for gcCnt < 5 {
		select {
		case <-gcOk:
			return
		default:
			runtime.GC()
			gcCnt++
		}
	}

	t.Fatalf("GatheredClientInitials is not GCed within 5 cycles")
}
