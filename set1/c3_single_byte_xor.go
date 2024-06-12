package set1

func CrackSingleByteXor(h string) string {
	_, _, cracked := bestByteAndScore(h)
	return cracked
}
