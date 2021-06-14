package main

// This program is used to test how to convert Yi's shared secret to the

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
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

func HexStringConvert() {
	// test convert byte arrary to string and convert back then du the xor
	//
	src := []byte("Go is an open source programming language.")
	orgStr := hex.EncodeToString(src)
	fmt.Printf("%s\n", orgStr)
	var a [32]byte
	copy(a[:], src)

	s := handshake{a}

	encodedStr := hex.EncodeToString(s.hash[:])

	fmt.Printf("encode: %s\n", encodedStr)

	// decode from string
	decoded, err := hex.DecodeString(encodedStr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decode: %s\n", decoded)

	fmt.Printf("After the xor loop: ")
	for i := 0; i < len(s.hash); i++ {
		s.hash[i] ^= src[i]
	}
	xorStr := hex.EncodeToString(s.hash[:])
	fmt.Printf("%s\n", xorStr)
	// Output:
	// 48656c6c6f

}

func UDPClient(){
	p :=  make([]byte, 2048)
	conn, err := net.Dial("udp", "127.0.0.1:1234")
	if err != nil {
		fmt.Printf("Some error %v", err)
		return
	}
	fmt.Fprintf(conn, "Hi UDP Server, How are you doing?")
	_, err = bufio.NewReader(conn).Read(p)
	if err == nil {
		fmt.Printf("%s\n", p)
	} else {
		fmt.Printf("Some error %v\n", err)
	}
	conn.Close()

}

func main() {
	UDPClient()
	HexStringConvert()
	ExampleDump()
}