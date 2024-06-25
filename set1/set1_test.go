package set1

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestC1(t *testing.T) {
	hex_input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	got, err := HexToBase64(hex_input)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestC2(t *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	want := "746865206b696420646f6e277420706c6179"

	got := FixedXor(input1, input2)
	assert.Equal(t, want, got)
}

func TestC3(t *testing.T) {
	cipher := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	want := "Cooking MC's like a pound of bacon"

	got := CrackSingleByteXor(cipher)
	assert.Equal(t, got, want)
}

func TestC4(t *testing.T) {
	contents, err := os.ReadFile("../inputs/4.txt")
	require.NoError(t, err, "Reading file")
	input := string(contents)
	want := "Now that the party is jumping\n"

	got := FindSingleXor(input)
	assert.Equal(t, want, got)
}

func TestC5(t *testing.T) {
	plaintext := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	got := RepeatedKeyXor(plaintext, key)
	assert.Equal(t, expected, got)
}

func TestBreakRepXor(t *testing.T) {
	// cyphertext, _ := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	cyphertext, err := os.ReadFile("../inputs/6.txt")
	require.NoError(t, err, "Opening file")

	t.Run("hamming distance", func(t *testing.T) {
		s1 := "this is a test"
		s2 := "wokka wokka!!!"
		expected := 37
		got := HammingDistance([]byte(s1), []byte(s2))
		assert.Equal(t, expected, got)
	})

	t.Run("find key size", func(t *testing.T) {
		keySize := findKeySize(cyphertext, 2, 40)
		assert.Equal(t, 3, keySize)
	})

	t.Run("Break repeared xor", func(t *testing.T) {
		plaintext := BreakRepeatedKeyXor(cyphertext)
		assert.Equal(t, string(plaintext), "")
	})
}
