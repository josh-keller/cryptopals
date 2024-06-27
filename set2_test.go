package main

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCS7Padding(t *testing.T) {
	t.Run("PKCS#7 padding", func(t *testing.T) {
		cases := []struct {
			input     string
			blocksize int
			expected  string
		}{
			{"YELLOW SUBMARINE", 20, "YELLOW SUBMARINE\x04\x04\x04\x04"},
			{"YELLOW SUBMARINE", 16, "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"},
		}
		for _, tc := range cases {
			padded := PadString(tc.input, tc.blocksize)
			assert.Equal(t, tc.expected, padded)
		}
	})

	t.Run("Test pad and strip", func(t *testing.T) {
		size, err := rand.Int(rand.Reader, big.NewInt(255))
		require.NoError(t, err)
		text := make([]byte, size.Int64())
		padded := PKCSPad(text, 16)
		stripped := StripPKCSPad(padded)
		assert.Equal(t, text, stripped)

	})
}

func TestCBC(t *testing.T) {
	t.Run("Decrypt File with CBC", func(t *testing.T) {
		b, err := ReadBase64File("./inputs/10.txt")
		require.NoError(t, err, "Reading file")
		key := []byte("YELLOW SUBMARINE")
		iv := bytes.Repeat([]byte{0}, 16)
		ptext := DecryptCBC(b, key, iv)
		assert.NotEmpty(t, ptext)
		assert.Contains(t, string(ptext), "So come on, everybody and sing this song")
		assert.Equal(t, 80, len(bytes.Split(ptext, []byte{'\n'})))
	})

	t.Run("Encrypt and decrypt CBC", func(t *testing.T) {
		plainBytes := make([]byte, 16*4)
		rand.Read(plainBytes)
		key := make([]byte, 16)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		cText := EncryptCBC(plainBytes, key, iv)
		pText := DecryptCBC(cText, key, iv)
		assert.Equal(t, plainBytes, pText)
	})
}
