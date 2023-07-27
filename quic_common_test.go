package clienthellod

import (
	"bytes"
	"testing"
)

var mapValueToVLI = map[uint64][]byte{
	0:                  {0x00},
	26:                 {0x1a},
	110:                {0x40, 0x6e},
	158:                {0x40, 0x9e},
	184:                {0x40, 0xb8},
	1212:               {0x44, 0xbc},
	30000:              {0x80, 0x00, 0x75, 0x30},
	6291456:            {0x80, 0x60, 0x00, 0x00},
	0x22d01138870c6f9f: {0xe2, 0xd0, 0x11, 0x38, 0x87, 0x0c, 0x6f, 0x9f},
}

func TestReadNextVLI(t *testing.T) {
	for v, vli := range mapValueToVLI {
		val, n, err := ReadNextVLI(bytes.NewReader(vli))
		if err != nil {
			t.Errorf("ReadNextVLI(%v) error: %v", vli, err)
		}
		if val != v {
			t.Errorf("ReadNextVLI(%v) = %v, want %v", vli, val, v)
		}
		if n != len(vli) {
			t.Errorf("ReadNextVLI(%v) = %v, want %v", vli, n, len(vli))
		}
	}
}

func TestDecodeVLI(t *testing.T) {
	for v, vli := range mapValueToVLI {
		val, err := DecodeVLI(vli)
		if err != nil {
			t.Errorf("DecodeVLI(%v) error: %v", vli, err)
		}
		if val != v {
			t.Errorf("DecodeVLI(%v) = %v, want %v", vli, val, v)
		}
	}
}

var mapQUICGREASEValues = map[uint64]bool{
	0x01:                false,
	0x02:                false,
	0x03:                false,
	0x04:                false,
	0x05:                false,
	0x06:                false,
	0x07:                false,
	0x08:                false,
	0x09:                false,
	0x0a:                false,
	0x0b:                false,
	0x0c:                false,
	0x0d:                false,
	0x0e:                false,
	0x0f:                false,
	0x10:                false,
	0x11:                false,
	0x12:                false,
	0x13:                false,
	0x14:                false,
	0x15:                false,
	0x16:                false,
	0x17:                false,
	0x18:                false,
	0x19:                false,
	0x1a:                false,
	27:                  true,
	31:                  false,
	58:                  true,
	89:                  true,
	2508523926926946207: true,
}

func TestIsGREASETransportParameter(t *testing.T) {
	for v, grease := range mapQUICGREASEValues {
		if IsGREASETransportParameter(v) != grease {
			t.Errorf("IsGREASETransportParameter(%v) = %v, want %v", v, !grease, grease)
		}
	}
}
