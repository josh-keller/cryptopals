package set1

import (
	"encoding/base64"
	"encoding/hex"
)

func HexToBase64(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}
