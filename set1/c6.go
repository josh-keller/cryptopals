package set1

import (
	"bytes"
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
		dist += bits.OnesCount8(longer[i] ^ shorter[i])
	}

	for ; i < len(longer); i++ {
		dist += bits.OnesCount8(longer[i])
	}

	return dist
}

func scoreKeySize(cyphertext []byte, keySize int) float64 {
	sliceSize := 2 * keySize
	numSamples := len(cyphertext) / sliceSize
	dist := 0

	for i := 0; i < numSamples; i++ {
		start := i * sliceSize
		stop := start + sliceSize
		mid := start + keySize
		dist += HammingDistance(cyphertext[start:mid], cyphertext[mid:stop])
	}

	return float64(dist) / float64(numSamples) / float64(keySize)
}

func findKeySize(cyphertext []byte, minKeySize, maxKeySize int) int {
	bestKeySize := 0
	minNormedDist := math.Inf(1)
	for ks := minKeySize; ks <= maxKeySize; ks++ {
		if len(cyphertext) < 2*ks {
			return bestKeySize
		}

		normedDist := scoreKeySize(cyphertext, ks)

		if normedDist < minNormedDist {
			minNormedDist = normedDist
			bestKeySize = ks
		}
	}

	return bestKeySize
}

func BreakRepeatedKeyXor(cypherBytes []byte) []byte {
	ks := findKeySize(cypherBytes, 2, 40)
	blocks := make([][]byte, ks)
	for i := 0; i < len(cypherBytes); i++ {
		blocks[i%ks] = append(blocks[i%ks], cypherBytes[i])
	}

	decoded := make([][]byte, ks)
	keyBytes := make([]byte, ks)

	for i, b := range blocks {
		keyBytes[i], _, decoded[i] = bestByteAndScore(b)
	}

	buffer := bytes.Buffer{}

	for i := 0; i < len(decoded[0]); i++ {
		for j := 0; j < len(decoded) && i < len(decoded[j]); j++ {
			buffer.WriteByte(decoded[j][i])
		}
	}

	return buffer.Bytes()
}
