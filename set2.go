package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
)

func PKCSPad(b []byte, blocksize int) []byte {
	if blocksize > 255 {
		panic("Cannot pad block more than 255")
	}

	padSize := blocksize - (len(b) % blocksize)
	return append(b, bytes.Repeat([]byte{uint8(padSize)}, padSize)...)
}

func StripPKCSPad(b []byte) []byte {
	last := len(b) - 1
	toStrip := b[last]
	firstPadIdx := len(b) - int(toStrip)
	for _, c := range b[firstPadIdx:] {
		if c != toStrip {
			panic("Invalid padding")
		}
	}

	return b[:firstPadIdx]
}

func PadString(s string, blocksize int) string {
	if blocksize > 255 {
		panic("Cannot pad block more than 255")
	}

	padSize := blocksize - (len(s) % blocksize)
	return s + string(bytes.Repeat([]byte{uint8(padSize)}, padSize))
}

func EncryptCBC(pText, key, iv []byte) []byte {
	blockSize := len(key)
	if len(key) != len(iv) {
		panic("Key and IV not the same size")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	prevCtext := iv
	cText := []byte{}
	pText = PKCSPad(pText, blockSize)

	for i := 0; i*blockSize < len(pText); i++ {
		currPtextBlock := pText[i*blockSize : (i+1)*blockSize]
		toEncrypt := FixedXor(currPtextBlock, prevCtext)
		cTextBlock := make([]byte, blockSize)
		cipher.Encrypt(cTextBlock, toEncrypt)
		cText = append(cText, cTextBlock...)
		prevCtext = cTextBlock
	}

	return cText
}

func DecryptCBC(ctext, key, iv []byte) []byte {
	blockSize := len(key)
	if len(key) != len(iv) {
		panic("Key and IV not the same size")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	prevCtext := iv
	toXor := make([]byte, blockSize)
	ptext := []byte{}

	for i := 0; i*blockSize < len(ctext); i += 1 {
		currCtextBlock := ctext[i*blockSize : (i+1)*blockSize]
		cipher.Decrypt(toXor, currCtextBlock)
		ptextBlock := FixedXor(toXor, prevCtext)
		ptext = append(ptext, ptextBlock...)
		prevCtext = currCtextBlock
	}

	return StripPKCSPad(ptext)
}

func EncryptionOracle(input []byte) []byte {
	return oracleHelper(input, rand.Intn(2))
}

func oracleHelper(input []byte, mode int) []byte {
	key := RandomBytes(16)
	prefix := RandomBytes(rand.Intn(6) + 5)
	postfix := RandomBytes(rand.Intn(6) + 5)
	toEncrypt := append(prefix, input...)
	toEncrypt = append(toEncrypt, postfix...)
	if mode == 0 {
		return EncryptCBC(toEncrypt, key, RandomBytes(16))
	} else {
		return EncryptECB(toEncrypt, key)
	}
}

func DetectMode(cText []byte) string {
	if MayBeECB(cText, 16) {
		return "ECB"
	}
	return "CBC"
}

var ByteAtTimeKey = RandomBytes(16)

const input12 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func EncryptECBConsistentKey(pText []byte) []byte {
	pText, err := base64.RawStdEncoding.AppendDecode(pText, []byte(input12))
	if err != nil {
		panic(err)
	}

	return EncryptECB(pText, ByteAtTimeKey)
}

func DetectBlockSize(f func([]byte) []byte) int {
	ptext := []byte("A")
	intitalCtext := f(ptext)
	for {
		ptext = append(ptext, 'A')
		nextCtext := f(ptext)
		sizeDiff := len(nextCtext) - len(intitalCtext)
		if sizeDiff > 0 {
			return sizeDiff
		}
	}
}

func CrackConsistentECB(f func([]byte) []byte) []byte {
	blockSize := DetectBlockSize(f)
	firstBlock := []byte{}

	for i := 1; i <= blockSize; i++ {
		firstBlock = append(firstBlock, CrackLastByte(f, blockSize, firstBlock))
	}

	fmt.Println(string(firstBlock))
	return firstBlock
}

func CrackLastByte(f func([]byte) []byte, blockSize int, known []byte) byte {
	prefix := bytes.Repeat([]byte{0}, blockSize-len(known)-1)
	dictionary := make(map[string]byte)
	challenge := append(prefix, known...)
	challenge = append(challenge, 0)
	for challengeByte := 0; challengeByte < 256; challengeByte++ {
		challenge[blockSize-1] = byte(challengeByte)
		encrpyted := f(challenge)
		dictionary[string(encrpyted[:blockSize])] = byte(challengeByte)
	}

	encrWithoutChallenge := f(prefix)
	return dictionary[string(encrWithoutChallenge[:blockSize])]
}
