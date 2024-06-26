package set1

import (
	"crypto/aes"
)

func DecryptAESECB(cyphertext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(cyphertext))

	for p := 0; p < len(plaintext); p += cipher.BlockSize() {
		cipher.Decrypt(plaintext[p:], cyphertext[p:])
	}
	return plaintext, nil
}
