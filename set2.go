package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
)

func PKCSPad(b []byte, blocksize int) []byte {
	if blocksize > 255 {
		panic("Cannot pad block more than 255")
	}

	padSize := blocksize - (len(b) % blocksize)
	return append(b, bytes.Repeat([]byte{uint8(padSize)}, padSize)...)
}

func StripPKCSPad(b []byte) []byte {
	if len(b) == 0 {
		return []byte{}
	}
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

func EncryptECBConsistentKey(pText []byte) []byte {
	return EncryptECB(pText, ByteAtTimeKey)
}

func DecryptECBConsistentKey(cText []byte) []byte {
	pText, err := DecryptECB(cText, ByteAtTimeKey)
	if err != nil {
		panic(err)
	}
	return pText
}

const input12 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

func AppendAndEncryptECBConsistentKey(pText []byte) []byte {
	pText, err := base64.RawStdEncoding.AppendDecode(pText, []byte(input12))
	if err != nil {
		panic(err)
	}

	return EncryptECBConsistentKey(pText)
}

func DetectBlockMsgSize(f func([]byte) []byte) (int, int) {
	ptext := []byte{}
	initialCtext := f(ptext)
	initLen := len(initialCtext)
	for i := 1; ; i++ {
		ptext = append(ptext, 'A')
		nextCtext := f(ptext)
		sizeDiff := len(nextCtext) - initLen
		if sizeDiff > 0 {
			return sizeDiff, initLen - i
		}
	}
}

func CrackConsistentECB(encrypt func([]byte) []byte) []byte {
	blockSize, msgSize := DetectBlockMsgSize(encrypt)
	message := []byte{}

	for i := 1; i <= msgSize; i++ {
		message = append(message, CrackNextByte(encrypt, blockSize, message))
	}

	return message
}

func CrackNextByte(encrypt func([]byte) []byte, blockSize int, known []byte) byte {
	dictionary := make(map[string]byte)
	extraKnownBytesCount := len(known) % blockSize
	tgtBlockStart := len(known) - extraKnownBytesCount
	prefixSize := blockSize - extraKnownBytesCount - 1

	prefix := bytes.Repeat([]byte{0}, prefixSize)
	challenge := append(prefix, known...)
	challenge = append(challenge, 0)

	for challengeByte := 0; challengeByte < 256; challengeByte++ {
		challenge[len(challenge)-1] = byte(challengeByte)
		cText := encrypt(challenge)
		targetBlock := cText[tgtBlockStart : tgtBlockStart+blockSize]
		dictionary[string(targetBlock)] = byte(challengeByte)
	}

	cTextWithoutChallenge := encrypt(prefix)
	targetBlock := cTextWithoutChallenge[tgtBlockStart : tgtBlockStart+blockSize]
	return dictionary[string(targetBlock)]
}

func KVParse(s string) map[string]string {
	result := make(map[string]string)
	fields := strings.Split(s, "&")
	for _, f := range fields {
		kv := strings.Split(f, "=")
		if len(kv) != 2 {
			panic("Invalid kv syntax")
		}

		result[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}

	return result
}

func ProfileFor(email string) string {
	encoded := strings.Replace(email, "=", "%3D", -1)
	encoded = strings.Replace(encoded, "&", "%26", -1)

	return fmt.Sprintf("email=%s&uid=10&role=user", encoded)
}

func GetEncryptedProfile(email string) []byte {
	profile := ProfileFor(email)
	return EncryptECBConsistentKey([]byte(profile))
}

func DecryptProfile(encryptedProfile []byte) string {
	return string(DecryptECBConsistentKey(encryptedProfile))
}

func CrackAdminProfile(f func(string) []byte) []byte {
	// Craft an email that begins the second block with 'admin' and then padding bytes
	paddedAdmin := "abcdefghijadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@abc.com"
	// Get this profile and extract the second block. It should have the encrypted 'admin' and padding blocks
	encrypted := f(paddedAdmin)
	endAdminBlock := encrypted[16:32]

	// Craft an email that will make the profile's last block have only 'user'. This can be replaced by the 'admin' block
	email := "abc@defgh.com"
	userProfile := f(email)
	result := append(userProfile[0:len(userProfile)-16], endAdminBlock...)

	return result
}
