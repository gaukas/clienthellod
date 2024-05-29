package clienthellod

import (
	"crypto/sha1" // skipcq: GSC-G505
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sort"

	"github.com/gaukas/clienthellod/internal/utils"
)

func updateArr(h hash.Hash, arr []byte) {
	binary.Write(h, binary.BigEndian, uint32(len(arr)))
	h.Write(arr)
}

func updateU32(h hash.Hash, i uint32) {
	binary.Write(h, binary.BigEndian, i)
}

func updateU64(h hash.Hash, i uint64) {
	binary.Write(h, binary.BigEndian, i)
}

type FingerprintID int64

func (id FingerprintID) AsHex() string {
	hid := make([]byte, 8)
	binary.BigEndian.PutUint64(hid, uint64(id))
	return hex.EncodeToString(hid)
}

// FingerprintNID calculates fingerprint Numeric ID of ClientHello.
// Fingerprint is defined by
func (ch *ClientHello) calcNumericID() (orig, norm int64) {
	for _, normalized := range []bool{false, true} {
		h := sha1.New() // skipcq: GO-S1025, GSC-G401,
		binary.Write(h, binary.BigEndian, uint16(ch.TLSRecordVersion))
		binary.Write(h, binary.BigEndian, uint16(ch.TLSHandshakeVersion))

		updateArr(h, utils.Uint16ToUint8(ch.CipherSuites))
		updateArr(h, ch.CompressionMethods)
		if normalized {
			updateArr(h, utils.Uint16ToUint8(ch.ExtensionsNormalized))
		} else {
			updateArr(h, utils.Uint16ToUint8(ch.Extensions))
		}
		updateArr(h, utils.Uint16ToUint8(ch.lengthPrefixedSupportedGroups))
		updateArr(h, ch.lengthPrefixedEcPointFormats)
		updateArr(h, utils.Uint16ToUint8(ch.lengthPrefixedSignatureAlgos))
		updateArr(h, ch.alpnWithLengths)
		updateArr(h, utils.Uint16ToUint8(ch.keyshareGroupsWithLengths))
		updateArr(h, ch.PSKKeyExchangeModes)
		updateArr(h, utils.Uint16ToUint8(ch.SupportedVersions))
		updateArr(h, ch.lengthPrefixedCertCompressAlgos)
		updateArr(h, ch.RecordSizeLimit)

		if normalized {
			norm = int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
		} else {
			orig = int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
		}
	}

	return
}

func (gci *GatheredClientInitials) calcNumericID() uint64 {
	h := sha1.New() // skipcq: GO-S1025, GSC-G401
	updateArr(h, gci.Packets[0].Header.Version)
	updateU32(h, gci.Packets[0].Header.DCIDLength)
	updateU32(h, gci.Packets[0].Header.SCIDLength)
	updateArr(h, gci.Packets[0].Header.PacketNumber)

	// merge, deduplicate, and sort all frames from all packets
	var allFrameIDs []uint8
	for _, p := range gci.Packets {
		allFrameIDs = append(allFrameIDs, p.Frames.FrameTypesUint8()...)
	}
	dedupAllFrameIDs := utils.DedupIntArr(allFrameIDs)
	sort.Slice(dedupAllFrameIDs, func(i, j int) bool {
		return dedupAllFrameIDs[i] < dedupAllFrameIDs[j]
	})
	updateArr(h, dedupAllFrameIDs)

	if gci.Packets[0].Header.HasToken {
		updateU32(h, TOKEN_PRESENT)
	} else {
		updateU32(h, TOKEN_ABSENT)
	}

	return binary.BigEndian.Uint64(h.Sum(nil)[0:8])
}
