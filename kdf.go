package secretr

import (
	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// DeriveKey uses Argon2id to produce a 32‐byte key from the password and salt.
// NIST SP 800-57: Argon2id is a memory-hard KDF recommended for password-based key derivation.
// Salt is unique per user, and output is suitable for AES-256.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}
