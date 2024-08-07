package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
		text := RandomBytes(int(size.Int64()))
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
		plainBytes := RandomBytes(16 * 16)
		key := make([]byte, 16)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		cText := EncryptCBC(plainBytes, key, iv)
		pText := DecryptCBC(cText, key, iv)
		assert.Equal(t, plainBytes, pText)
	})
}

func TestOracle(t *testing.T) {
	t.Run("Test Oracle", func(t *testing.T) {
		runs := 1000.0
		correct := 0.0
		for i := 0; i < 1000; i++ {
			pText := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			cText := oracleHelper(pText, i%2)
			mode := DetectMode(cText)
			if mode == "ECB" && i%2 == 1 {
				correct++
			} else if mode == "CBC" && i%2 == 0 {
				correct++
			}
		}
		assert.Equal(t, runs, correct)
	})
}

func TestECBDecryptOneByte(t *testing.T) {
	decodedString, _ := base64.RawStdEncoding.DecodeString(input12)
	t.Run("Consistent key func produces output", func(t *testing.T) {
		cText := AppendAndEncryptECBConsistentKey([]byte("hello"))
		assert.NotEmpty(t, cText)
	})

	t.Run("Can find block size and message size of consistent key func", func(t *testing.T) {
		blockSize, msgSize := DetectBlockMsgSize(AppendAndEncryptECBConsistentKey)
		assert.Equal(t, 16, blockSize)
		assert.Equal(t, len(decodedString), msgSize)
	})

	t.Run("Detect consistent key func is using ECB", func(t *testing.T) {
		blockSize, _ := DetectBlockMsgSize(AppendAndEncryptECBConsistentKey)
		pText := bytes.Repeat([]byte{'A'}, blockSize*3)
		mode := DetectMode(AppendAndEncryptECBConsistentKey(pText))
		assert.Equal(t, "ECB", mode)
	})

	t.Run("Decrypt first block", func(t *testing.T) {
		expected := decodedString[:16]
		message := CrackConsistentECB(AppendAndEncryptECBConsistentKey)
		assert.Equal(t, expected, message[:16])
	})

	t.Run("Crack ECB", func(t *testing.T) {
		expected := decodedString
		decrypted := CrackConsistentECB(AppendAndEncryptECBConsistentKey)
		assert.Equal(t, len(expected), len(decrypted))
		assert.Equal(t, expected, decrypted)
	})
}

func TestChallenge13(t *testing.T) {
	email := "thisIsMyEmail@example.com"
	t.Run("test kvparser", func(t *testing.T) {
		expected := map[string]string{
			"foo": "bar",
			"baz": "qux",
			"zap": "zazzle",
		}
		got := KVParse("foo=bar&baz=qux&zap=zazzle")
		assert.Equal(t, expected, got)
	})
	t.Run("ProfileFor creates profile", func(t *testing.T) {
		expected := "email=foo@bar.com&uid=10&role=user"
		got := ProfileFor("foo@bar.com")
		assert.Equal(t, expected, got)
	})
	t.Run("ProfileFor does not allow unescaped user input", func(t *testing.T) {
		expected := `email=foo@bar.com%26profile%3Dadmin&uid=10&role=user`
		got := ProfileFor("foo@bar.com&profile=admin")
		assert.Equal(t, expected, got)
	})
	t.Run("Get encrypted profile returns ciphertext", func(t *testing.T) {
		ctext := GetEncryptedProfile(email)
		assert.NotEmpty(t, ctext)
	})
	t.Run("Decrypted profile mathes what was encrypted", func(t *testing.T) {
		profile := ProfileFor(email)
		encrypted := GetEncryptedProfile(email)
		decrypted := DecryptProfile(encrypted)
		assert.Equal(t, profile, decrypted)
	})
	t.Run("MakeAdmin returns an admin profile", func(t *testing.T) {
		adminCipherText := CrackAdminProfile(GetEncryptedProfile)
		decrypted := string(DecryptProfile(adminCipherText))
		assert.Contains(t, decrypted, "&role=admin")
		fmt.Println(decrypted)

	})
}
