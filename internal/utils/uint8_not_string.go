package utils

import (
	"fmt"
	"strings"
)

type Uint8Arr []uint8

func (u Uint8Arr) MarshalJSON() ([]byte, error) {
	var result string
	if u == nil {
		result = "[]"
	} else {
		result = strings.Join(strings.Fields(fmt.Sprintf("%d", u)), ",")
	}
	return []byte(result), nil
}
