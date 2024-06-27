package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
)

func HexToBase64(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

func FixedXor(b1, b2 []byte) []byte {
	for i := range b1 {
		b1[i] ^= b2[i]
	}

	return b1
}

func CrackSingleByteXor(b []byte) []byte {
	_, _, cracked := bestByteAndScore(b)
	return cracked
}

func FindSingleXor(lines [][]byte) string {
	bestScore := 1000.0
	output := ""
	// Get the score of the highest single xor
	for _, l := range lines {
		_, score, out := bestByteAndScore(l)
		if score < bestScore {
			bestScore = score
			output = string(out)
		}
	}

	return output
}

func RepeatedKeyXor(plaintext, key string) string {
	keyBytes := []byte(key)
	cypherText := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i++ {
		cypherText[i] = plaintext[i] ^ keyBytes[i%len(keyBytes)]
	}

	return hex.EncodeToString(cypherText)
}

func HammingDistance(b1, b2 []byte) int {
	var longer, shorter []byte
	if len(b1) > len(b2) {
		longer = b1
		shorter = b2
	} else {
		longer = b2
		shorter = b1
	}

	dist := 0
	i := 0

	for ; i < len(shorter); i++ {
		dist += bits.OnesCount8(longer[i] ^ shorter[i])
	}

	for ; i < len(longer); i++ {
		dist += bits.OnesCount8(longer[i])
	}

	return dist
}

func scoreKeySize(cyphertext []byte, keySize int) float64 {
	sliceSize := 2 * keySize
	numSamples := len(cyphertext) / sliceSize
	dist := 0

	for i := 0; i < numSamples; i++ {
		start := i * sliceSize
		stop := start + sliceSize
		mid := start + keySize
		dist += HammingDistance(cyphertext[start:mid], cyphertext[mid:stop])
	}

	return float64(dist) / float64(numSamples) / float64(keySize)
}

func findKeySize(cyphertext []byte, minKeySize, maxKeySize int) int {
	bestKeySize := 0
	minNormedDist := math.Inf(1)
	for ks := minKeySize; ks <= maxKeySize; ks++ {
		if len(cyphertext) < 2*ks {
			return bestKeySize
		}

		normedDist := scoreKeySize(cyphertext, ks)

		if normedDist < minNormedDist {
			minNormedDist = normedDist
			bestKeySize = ks
		}
	}

	return bestKeySize
}

func BreakRepeatedKeyXor(cypherBytes []byte) []byte {
	ks := findKeySize(cypherBytes, 2, 40)
	blocks := make([][]byte, ks)
	for i := 0; i < len(cypherBytes); i++ {
		blocks[i%ks] = append(blocks[i%ks], cypherBytes[i])
	}

	decoded := make([][]byte, ks)
	keyBytes := make([]byte, ks)

	for i, b := range blocks {
		keyBytes[i], _, decoded[i] = bestByteAndScore(b)
	}

	buffer := bytes.Buffer{}

	for i := 0; i < len(decoded[0]); i++ {
		for j := 0; j < len(decoded) && i < len(decoded[j]); j++ {
			buffer.WriteByte(decoded[j][i])
		}
	}

	return buffer.Bytes()
}

// TODO: make interface consitent for error handling
func EncryptECB(pText []byte, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	toEncrypt := PKCSPad(pText, cipher.BlockSize())
	cText := make([]byte, len(toEncrypt))
	for p := 0; p < len(toEncrypt); p += cipher.BlockSize() {
		cipher.Encrypt(cText[p:], toEncrypt[p:])
	}

	return cText
}

func DecryptECB(cyphertext []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(cyphertext))

	for p := 0; p < len(plaintext); p += cipher.BlockSize() {
		cipher.Decrypt(plaintext[p:], cyphertext[p:])
	}
	return StripPKCSPad(plaintext), nil
}

func DetectAESECB(lines [][]byte, blocksize int) [][]byte {
	hits := make([][]byte, 0)
	for _, l := range lines {
		if MayBeECB(l, blocksize) {
			hits = append(hits, l)
		}
	}

	return hits
}

func MayBeECB(b []byte, blocksize int) bool {
	blocks := make(map[string]struct{})
	if len(b)%blocksize != 0 {
		return false
	}
	for i := 0; i+blocksize < len(b); i += blocksize {
		hexBlock := string(b[i : i+blocksize])
		if _, exists := blocks[hexBlock]; exists {
			return true
		}
		blocks[hexBlock] = struct{}{}
	}

	return false
}
