package utils

import (
	"encoding/json"
	"testing"
)

type TestStruct struct {
	Name   string   `json:"name"`
	Age    int      `json:"age"`
	Topics Uint8Arr `json:"topics"`
}

func TestUint8Arr(t *testing.T) {
	testStruct := TestStruct{
		Name:   "gaukas",
		Age:    18,
		Topics: Uint8Arr{'H', 'e', 'l', 'l', 'o'},
	}

	// testStruct: {Name:gaukas Age:18 Topics:[72 101 108 108 111]}
	_, err := json.Marshal(testStruct)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	// t.Logf("json.Marshal: %s", m)
}
