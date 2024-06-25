package set1

import "encoding/hex"

func RepeatedKeyXor(plaintext, key string) string {
	keyBytes := []byte(key)
	cypherText := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		cypherText[i] = plaintext[i] ^ keyBytes[i%len(keyBytes)]
	}

	return hex.EncodeToString(cypherText)
}
