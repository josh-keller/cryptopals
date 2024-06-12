package set1

import (
	"encoding/hex"
)

func FixedXor(in1, in2 string) string {
	b1, err := hex.DecodeString(in1)
	if err != nil {
		panic(err)
	}
	b2, err := hex.DecodeString(in2)
	if err != nil {
		panic(err)
	}
	for i := range b1 {
		b1[i] ^= b2[i]
	}

	return hex.EncodeToString(b1)
}
