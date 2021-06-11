package main

// This program is used to test how to convert Yi's shared secret to the

import (
	"encoding/hex"
	"fmt"
)


func ExampleDump() {
	content := []byte("Go is an open source programming language.")

	//fmt.Printf("%s", hex.Dump(content))
	stringdata := hex.Dump(content)

	fmt.Printf(stringdata)

	// Output:
	// 00000000  47 6f 20 69 73 20 61 6e  20 6f 70 65 6e 20 73 6f  |Go is an open so|
	// 00000010  75 72 63 65 20 70 72 6f  67 72 61 6d 6d 69 6e 67  |urce programming|
	// 00000020  20 6c 61 6e 67 75 61 67  65 2e                    | language.|
}

type handshake struct {
	hash [32]byte
}

func ExampleEncodeToString() {
	src := []byte("Go is an open source programming language.")

	var a [32]byte
	copy(a[:], src)


	s := handshake{a}

	encodedStr := hex.EncodeToString(s.hash[:])

	fmt.Printf("%s\n", encodedStr)

	// Output:
	// 48656c6c6f
}


func main() {
	ExampleEncodeToString()
	ExampleDump()
}