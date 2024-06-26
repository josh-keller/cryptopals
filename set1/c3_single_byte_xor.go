package set1

func CrackSingleByteXor(b []byte) []byte {
	_, _, cracked := bestByteAndScore(b)
	return cracked
}
