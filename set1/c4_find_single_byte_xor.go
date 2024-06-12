package set1

import (
	"strings"
)

func FindSingleXor(input string) string {
	tmp := strings.Fields(input)
	lines := make([]string, 0, len(tmp))
	for _, l := range tmp {
		if len(l) == 60 {
			lines = append(lines, l)
		}
	}

	bestScore := 1000.0
	output := ""
	// Get the score of the highest single xor
	for _, l := range lines {
		_, score, out := bestByteAndScore(l)
		if score < bestScore {
			bestScore = score
			output = out
		}
	}

	return output
}
