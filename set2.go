package main

import "bytes"

func PadString(s string, blocksize int) string {
	if blocksize > 255 {
		panic("Cannot pad block more than 255")
	}

	padSize := blocksize - (len(s) % blocksize)
	return s + string(bytes.Repeat([]byte{uint8(padSize)}, padSize))
}
