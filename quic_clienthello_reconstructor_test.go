package clienthellod_test

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"math"
	"math/big"
	"math/rand"
	"testing"

	crand "crypto/rand"

	. "github.com/gaukas/clienthellod"
)

var (
	//go:embed internal/testdata/QUIC_Frame_Chrome_124_CRYPTO_0.bin
	quicFrames_Chrome124_CRYPTO_0 []byte
	//go:embed internal/testdata/QUIC_Frame_Chrome_124_CRYPTO_1191.bin
	quicFrames_Chrome124_CRYPTO_1191 []byte
	//go:embed internal/testdata/QUIC_Frame_Chrome_124_CRYPTO_1287.bin
	quicFrames_Chrome124_CRYPTO_1287 []byte
	//go:embed internal/testdata/QUIC_Frame_Chrome_124_CRYPTO_1561.bin
	quicFrames_Chrome124_CRYPTO_1561 []byte
	//go:embed internal/testdata/QUIC_Frame_Chrome_124_CRYPTO_1663.bin
	quicFrames_Chrome124_CRYPTO_1663 []byte

	//go:embed internal/testdata/QUIC_ClientHello_Chrome_124.bin
	quicClientHelloTruth_Chrome124 []byte
)

var Chrome124_CRYPTO []struct {
	offset uint64
	pl     []byte
} = []struct {
	offset uint64
	pl     []byte
}{
	{0, quicFrames_Chrome124_CRYPTO_0},
	{1191, quicFrames_Chrome124_CRYPTO_1191},
	{1287, quicFrames_Chrome124_CRYPTO_1287},
	{1561, quicFrames_Chrome124_CRYPTO_1561},
	{1663, quicFrames_Chrome124_CRYPTO_1663},
}

func TestQUICClientHelloReconstructor(t *testing.T) {
	r := NewQUICClientHelloReconstructor()

	// shuffle the fragments
	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		t.Fatal(err)
	} else {
		rand.New(rand.NewSource(randInt64.Int64())).Shuffle(len(Chrome124_CRYPTO), func(i, j int) { // skipcq: GSC-G404
			Chrome124_CRYPTO[i], Chrome124_CRYPTO[j] = Chrome124_CRYPTO[j], Chrome124_CRYPTO[i]
		})
	}

	for i, frag := range Chrome124_CRYPTO {
		if err := r.AddCRYPTOFragment(frag.offset, frag.pl); err != nil {
			if i == len(Chrome124_CRYPTO)-1 && errors.Is(err, io.EOF) {
				break
			} else {
				t.Fatal(err)
			}
		}
	}

	if !bytes.Equal(r.ReconstructAsBytes(), quicClientHelloTruth_Chrome124) {
		t.Fatalf("Reassembled ClientHello mismatch")
	}
}
