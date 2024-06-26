package set1

import (
	"encoding/hex"
)

func FindSingleXor(lines [][]byte) string {
	bestScore := 1000.0
	output := ""
	// Get the score of the highest single xor
	for _, l := range lines {
		buffer := make([]byte, len(l)/2)
		_, err := hex.Decode(buffer, l)
		if err != nil {
			panic(err)
		}
		_, score, out := bestByteAndScore(buffer)
		if score < bestScore {
			bestScore = score
			output = string(out)
		}
	}

	return output
}
