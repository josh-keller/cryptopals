package set1

func DetectAESECB(lines [][]byte, blocksize int) [][]byte {
	hits := make([][]byte, 0)
	for _, l := range lines {
		if MayBeECB(string(l), blocksize) {
			hits = append(hits, l)
		}
	}

	return hits
}

func MayBeECB(s string, blocksize int) bool {
	blocks := make(map[string]struct{})
	if len(s)%(blocksize*2) != 0 {
		return false
	}
	for i := 0; i+2*blocksize < len(s); i += 2 * blocksize {
		hexBlock := s[i : i+2*blocksize]
		if _, exists := blocks[hexBlock]; exists {
			return true
		}
		blocks[hexBlock] = struct{}{}
	}

	return false
}
