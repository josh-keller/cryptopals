package set1

import (
	"bytes"
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

func ReadHexLines(filename string) ([][]byte, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return bytes.Split(contents, []byte{'\n'}), nil
}
