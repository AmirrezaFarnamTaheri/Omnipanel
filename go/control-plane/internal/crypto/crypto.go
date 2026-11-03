package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// HashPassword hashes a password using scrypt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 64)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(dk)
	return encoded, nil
}

// VerifyPassword checks a password against an scrypt hash.
func VerifyPassword(encodedHash, password string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 2 {
		return false, errors.New("invalid hash format")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}
	dk, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, err
	}
	candidate, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 64)
	if err != nil {
		return false, err
	}
	return subtleConstantTimeCompare(candidate, dk), nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given 32-byte key.
func Encrypt(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext.
func Decrypt(key []byte, ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

// Hash256 returns the SHA-256 hash of data as a hex string.
func Hash256(data []byte) string {
	return hexEncode(sha256.Sum256(data))
}

func subtleConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := range a {
		result |= int(a[i] ^ b[i])
	}
	return result == 0
}

func hexEncode(b [32]byte) string {
	const chars = "0123456789abcdef"
	var out [64]byte
	for i, v := range b {
		out[i*2] = chars[v>>4]
		out[i*2+1] = chars[v&0x0f]
	}
	return string(out[:])
}
