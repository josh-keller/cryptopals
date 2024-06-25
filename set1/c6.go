package set1

import (
	"encoding/hex"
	"math"
	"math/bits"
)

func HammingDistance(b1, b2 []byte) int {
	var longer, shorter []byte
	if len(b1) > len(b2) {
		longer = b1
		shorter = b2
	} else {
		longer = b2
		shorter = b1
	}

	dist := 0
	i := 0

	for ; i < len(shorter); i++ {
		diff := bits.OnesCount8(longer[i] ^ shorter[i])
		dist += int(math.Abs(float64(diff)))
	}

	for ; i < len(longer); i++ {
		dist += bits.OnesCount8(longer[i])
	}

	return dist
}

func findKeySize(cyphertext []byte, minKeySize, maxKeySize int) int {
	bestKeySize := 0
	minNormedDist := math.Inf(1)
	for ks := minKeySize; ks <= maxKeySize; ks++ {
		if len(cyphertext) < 4*ks {
			return bestKeySize
		}

		chunk1 := cyphertext[0:ks]
		chunk2 := cyphertext[ks : 2*ks]
		chunk3 := cyphertext[2*ks : 3*ks]
		chunk4 := cyphertext[3*ks : 4*ks]
		hamming := HammingDistance(chunk1, chunk2)
		hamming += HammingDistance(chunk1, chunk3)
		hamming += HammingDistance(chunk1, chunk4)
		normedDist := float64(hamming) / float64(ks)

		if normedDist < minNormedDist {
			minNormedDist = normedDist
			bestKeySize = ks
		}
	}

	return bestKeySize
}

func BreakRepeatedKeyXor(cyphertext []byte) []byte {
	ks := findKeySize(cyphertext, 2, 40)
	blocks := make([][]byte, ks)
	for i := 0; i < len(cyphertext); i++ {
		blocks[i%ks] = append(blocks[i%ks], cyphertext[i])
	}

	decoded := make([][]byte, ks)

	for i, b := range blocks {
		decoded[i] = []byte(CrackSingleByteXor(hex.EncodeToString(b)))
	}

	return []byte{}
}
