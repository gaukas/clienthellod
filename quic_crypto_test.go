package clienthellod_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/gaukas/clienthellod"
)

func TestClientInitialKeysCalc(t *testing.T) {
	initialRandom := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
	}

	clientKey, clientIV, clientHpKey, err := ClientInitialKeysCalc(initialRandom)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(clientKey, []byte{
		0xb1, 0x4b, 0x91, 0x81, 0x24, 0xfd, 0xa5, 0xc8,
		0xd7, 0x98, 0x47, 0x60, 0x2f, 0xa3, 0x52, 0x0b,
	}) {
		t.Fatalf("clientKey mismatch, got %x", clientKey)
	}

	if !bytes.Equal(clientIV, []byte{
		0xdd, 0xbc, 0x15, 0xde, 0xa8, 0x09, 0x25, 0xa5, 0x56, 0x86, 0xa7, 0xdf,
	}) {
		t.Fatalf("clientIV mismatch, got %x", clientIV)
	}

	if !bytes.Equal(clientHpKey, []byte{
		0x6d, 0xf4, 0xe9, 0xd7, 0x37, 0xcd, 0xf7, 0x14,
		0x71, 0x1d, 0x7c, 0x61, 0x7e, 0xe8, 0x29, 0x81,
	}) {
		t.Fatalf("clientHpKey mismatch, got %x", clientHpKey)
	}
}

func TestComputeHeaderProtection(t *testing.T) {
	hp, err := ComputeHeaderProtection(
		[]byte{
			0x6d, 0xf4, 0xe9, 0xd7, 0x37, 0xcd, 0xf7, 0x14,
			0x71, 0x1d, 0x7c, 0x61, 0x7e, 0xe8, 0x29, 0x81,
		},
		[]byte{
			0xed, 0x78, 0x71, 0x6b, 0xe9, 0x71, 0x1b, 0xa4,
			0x98, 0xb7, 0xed, 0x86, 0x84, 0x43, 0xbb, 0x2e,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(hp, []byte{0xed, 0x98, 0x95, 0xbb, 0x15}) {
		t.Fatalf("unexpected header protection: %x", hp)
	}
}

func TestDecryptAES128GCM(t *testing.T) {
	var recordNum uint64 = 0x00
	iv, _ := hex.DecodeString("ddbc15dea80925a55686a7df")
	key, _ := hex.DecodeString("b14b918124fda5c8d79847602fa3520b")
	cipherText, _ := hex.DecodeString("1c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efafffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08")
	recdata, _ := hex.DecodeString("c00000000108000102030405060705635f63696400410300")
	authtag, _ := hex.DecodeString("b3b7241ef6646a6c86e5c62ce08be099")

	plaintext, err := DecryptAES128GCM(iv, recordNum, key, cipherText, recdata, authtag)
	if err != nil {
		t.Fatal(err)
	}

	expectedPlaintext, _ := hex.DecodeString("060040ee010000ea0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000006130113021303010000bb0000001800160000136578616d706c652e756c666865696d2e6e6574000a00080006001d001700180010000b00090870696e672f312e30000d00140012040308040401050308050501080606010201003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254002d00020101002b00030203040039003103048000fff7040480a0000005048010000006048010000007048010000008010a09010a0a01030b01190f05635f636964")

	if !bytes.Equal(plaintext, expectedPlaintext) {
		t.Fatalf("unexpected plaintext: %x", plaintext)
	}
}
