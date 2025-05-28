package secretr

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// DeriveKey uses Argon2id to produce a 32‐byte key from the password and salt.
// It ensures secure derivation of an encryption key.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func SignData(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func VerifySignature(data, key, signature []byte) bool {
	expected := SignData(data, key)
	return hmac.Equal(expected, signature)
}

func HashData(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
