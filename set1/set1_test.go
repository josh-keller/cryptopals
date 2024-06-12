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
