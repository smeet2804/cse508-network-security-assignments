package main

import (
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"sync"
)

var CHUNK_SIZE = 1 * 1024 // Define your chunk size here

// Handle the traffic encryption
func handleTrafficEncrypt(reader io.Reader, writer io.Writer, wg *sync.WaitGroup, aesGCM cipher.AEAD, errChan chan<- error) {
	defer wg.Done()

	buffer := make([]byte, CHUNK_SIZE-100)
	for {
		n, err := reader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading: %v\n", err)
			}
			break
		}
		if n == 0 {
			break
		}
		chunk := buffer[:n]
		data, err := encrypt(chunk, aesGCM)
		// log.Printf("Data: %v\n", data)

		if err != nil {
			log.Printf("Error during encryption: %v\n", err)
			errChan <- fmt.Errorf("error while encrypting")
			break
		}
		dataLen := len(data)
		log.Printf("Data length: %d\n", dataLen)
		data = append([]byte{byte(dataLen >> 8), byte(dataLen)}, data...)

		if len(data) < CHUNK_SIZE {
			data = append(data, make([]byte, CHUNK_SIZE-len(data))...)
		}
		log.Printf("Data length after padding: %d\n", len(data))
		_, err = writer.Write(data)
		if err != nil {
			log.Printf("Error writing: %v\n", err)
			break
		}

	}
	log.Printf("Done with encryption\n\n\n\n")
}

func handleTrafficDecrypt(reader io.Reader, writer io.Writer, wg *sync.WaitGroup, aesGCM cipher.AEAD, errChan chan<- error) {
	defer wg.Done()
	buffer := make([]byte, CHUNK_SIZE)

	for {
		n, err := io.ReadFull(reader, buffer)
		if err != nil {
			if err == io.EOF {
				break
			} else if err == io.ErrUnexpectedEOF {
				errChan <- fmt.Errorf("unexpected end of file while reading full chunk")
				return
			} else {
				errChan <- fmt.Errorf("read error: %v", err)
				return
			}
		}

		log.Printf("Read %d bytes\n", n)
		dataLen := int(buffer[0])<<8 | int(buffer[1])
		if dataLen > CHUNK_SIZE-2 {
			errChan <- fmt.Errorf("invalid data length")
			return
		}

		data, decryptErr := decrypt(buffer[2:dataLen+2], aesGCM)
		if decryptErr != nil {
			errChan <- fmt.Errorf("error while decrypting: %v", decryptErr)
			return
		}

		if _, writeErr := writer.Write(data); writeErr != nil {
			errChan <- fmt.Errorf("write error: %v", writeErr)
			return
		}
	}
}
