package set1

import (
	"encoding/base64"
	"io"
	"os"
)

func ReadBase64File(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	decoder := base64.NewDecoder(base64.RawStdEncoding.WithPadding('='), file)
	return io.ReadAll(decoder)
}
