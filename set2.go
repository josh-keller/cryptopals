package main

import (
	"bytes"
	"crypto/aes"
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
