package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
}
