package set1

import (
	"encoding/hex"
	"math"
)

func calculateWeight(bs []byte) float64 {
	freq := make(map[byte]int)
	ignored := 0
	for _, b := range bs {
		if b >= 32 && b <= 126 {
			freq[b]++
		} else if b == 9 || b == 10 || b == 13 {
			freq[b]++
		} else {
			return math.Inf(1)
		}
	}

	chi2 := 0.0
	len := len(bs) - ignored
	for i := byte(0); i < 128; i++ {
		observed := float64(freq[i])
		exFreq, exists := englishFreq[i]
		if !exists {
			ignored++
			continue
		}
		expected := float64(len) * exFreq
		difference := observed - expected
		chi2 += difference * difference / expected
	}

	return chi2
}

func bestByteAndScore(h string) (byte, float64, string) {
	bs, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	xored := make([]byte, len(bs))
	copy(xored, bs)
	bestWeight := 1000.0
	currBest := make([]byte, len(bs))
	bestByte := 0

	for xorByte := 0; xorByte < 256; xorByte++ {
		for i := range bs {
			xored[i] = bs[i] ^ byte(xorByte)
		}
		weight := calculateWeight(xored)
		if weight < bestWeight {
			bestWeight = weight
			copy(currBest, xored)
			bestByte = xorByte
		}
	}

	return byte(bestByte), bestWeight, string(currBest)
}

func CrackSingleByteXor(h string) string {
	_, _, cracked := bestByteAndScore(h)
	return cracked
}
