package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

// Run the client mode of the application (connect to a server)
func runClient(destination string, password []byte) {
	conn, err := net.Dial("tcp", destination)
	if err != nil {
		log.Fatalf("Failed to connect to destination %s: %v\n", destination, err)
	}
	defer conn.Close()
	log.Printf("Connected to %s\n", destination)
	salt := make([]byte, saltSize)
	_, err = io.ReadFull(conn, salt)
	log.Printf("Salt: %v\n", salt)
	if err != nil {
		log.Fatalf("Failed to read salt from server: %v\n", err)
	}
	key := deriveKey(password, salt)
	log.Printf("Key: %v\n", key)
	aes, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create AES cipher: %v\n", err)
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		log.Fatalf("Failed to create AES-GCM: %v\n", err)
	}

	wg := &sync.WaitGroup{}
	errChan := make(chan error, 2)
	wg.Add(2)

	go handleTrafficEncrypt(os.Stdin, conn, wg, aesGCM, errChan)

	go handleTrafficDecrypt(conn, os.Stdout, wg, aesGCM, errChan)

	go func() {
		for err := range errChan {
			fmt.Printf("Received an error on client side: %v\n", err)
			os.Exit(1)
		}
	}()
	// close(errChan)
	wg.Wait()
}
