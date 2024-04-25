package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const saltSize = 16

// Generate a random salt
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// Derive a key from the password using PBKDF2
func deriveKey(password []byte, salt []byte) []byte {
	iterations := 100000
	return pbkdf2.Key(password, salt, iterations, 32, sha256.New)
}

// Encrypt a chunk of data using AES-GCM
func encrypt(data []byte, aesGCM cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesGCM.Seal(nonce, nonce, data, nil), nil
}

// Decrypt a chunk of data using AES-GCM
func decrypt(data []byte, aesGCM cipher.AEAD) ([]byte, error) {
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
