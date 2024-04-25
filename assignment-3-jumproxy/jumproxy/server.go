package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
	"net"
	"sync"
)

func runProxy(destination string, password []byte) {
	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v\n", listenPort, err)
	}
	defer listener.Close()

	log.Printf("Proxy listening on port %s, forwarding to %s\n", listenPort, destination)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		log.Printf("Accepted connection from %s\n", conn.RemoteAddr())
		go handleConnection(conn, destination, password)
	}
}

func handleConnection(conn net.Conn, destination string, password []byte) {
	defer conn.Close()

	remoteConn, err := net.Dial("tcp", destination)
	if err != nil {
		log.Printf("Failed to connect to remote destination %s: %v\n", destination, err)
		return
	}
	salt, err := generateSalt()
	if err != nil {
		log.Printf("Failed to generate salt: %v\n", err)
		return
	}
	log.Printf("Salt: %v\n", salt)
	_, err = conn.Write(salt)
	if err != nil {
		log.Printf("Failed to write salt to remote destination: %v\n", err)
		return
	}
	key := deriveKey(password, salt)
	log.Printf("Key: %v\n", key)
	aes, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Failed to create AES cipher: %v\n", err)
		return
	}
	aesGCM, err := cipher.NewGCM(aes)
	if err != nil {
		log.Printf("Failed to create AES-GCM: %v\n", err)
		return
	}

	defer remoteConn.Close()

	wg := &sync.WaitGroup{}
	errChan := make(chan error, 2) // Buffered to avoid blocking when sending errors

	wg.Add(2)

	// Handles Traffic from server jumproxy to destination service
	go handleTrafficDecrypt(conn, remoteConn, wg, aesGCM, errChan)
	// Traffic from remote to local (encryption)
	go handleTrafficEncrypt(remoteConn, conn, wg, aesGCM, errChan)
	go func() {
		for err := range errChan {
			log.Printf("Received an error: %v\n", err)
			log.Printf("Closing connection %s\n", conn.RemoteAddr())
			data := []byte("Error: " + err.Error())
			encryptData, err := encrypt(data, aesGCM)
			if err != nil {
				log.Printf("Error encrypting error message: %v\n", err)
				return
			}
			lenData := len(encryptData)
			encryptData = append([]byte{byte(lenData >> 8), byte(lenData)}, encryptData...)
			encryptData = append(encryptData, make([]byte, CHUNK_SIZE-len(encryptData))...)
			conn.Write(encryptData)
			conn.Close()
		}
	}()
	wg.Wait()
	log.Printf("Connection closed ---------------------")
	// close(errChan) // Safe to close the channel since all sends are complete

}
