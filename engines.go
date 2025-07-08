package secretr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// GenerateDBCredential simulates on-the-fly generation of database credentials.
// NIST SP 800-57: These are ephemeral credentials, not cryptographic keys.
// To comply, we will generate a per-credential AES-256 key and encrypt the password.
func GenerateDBCredential(engine string) (map[string]string, error) {
	var userPrefix string
	switch engine {
	case "postgres":
		userPrefix = "pguser"
	case "mysql":
		userPrefix = "myuser"
	default:
		return nil, fmt.Errorf("unsupported database engine")
	}
	user := fmt.Sprintf("%s_%s", userPrefix, GenerateRandomString(8))
	pass := GenerateRandomString(16)
	expiry := time.Now().Add(5 * time.Minute).Format(time.RFC3339)

	// Generate a random AES-256 key for this credential
	key, err := generateRandomBytes(32)
	if err != nil {
		return nil, err
	}
	encPass, err := encryptEphemeral(pass, key)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"user":      user,
		"enc_pass":  encPass,
		"expires":   expiry,
		"key_b64":   base64.StdEncoding.EncodeToString(key),
		"algorithm": "AES-256-GCM",
	}, nil
}

// GenerateCloudToken simulates generating a token for a cloud provider.
// NIST SP 800-57: These are ephemeral tokens, not cryptographic keys.
// To comply, we will generate a per-token AES-256 key and encrypt the token.
func GenerateCloudToken(provider string) (string, error) {
	var prefix string
	switch provider {
	case "aws":
		prefix = "aws-token"
	case "azure":
		prefix = "azure-token"
	case "gcp":
		prefix = "gcp-token"
	default:
		return "", fmt.Errorf("unsupported cloud provider")
	}
	token := fmt.Sprintf("%s-%s", prefix, GenerateRandomString(20))
	key, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}
	encToken, err := encryptEphemeral(token, key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s|%s|%s", encToken, base64.StdEncoding.EncodeToString(key), "AES-256-GCM"), nil
}

// encryptEphemeral encrypts data with a one-time AES-256-GCM key.
func encryptEphemeral(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// WrapResponse encrypts sensitive data into a one‑time wrapping token.
// For simplicity, we reuse TransitEncrypt.
func WrapResponse(v *Secretr, data string) (string, error) {
	encrypted, err := v.TransitEncrypt(data)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

// UnwrapResponse returns the original data from a wrapping token.
func UnwrapResponse(v *Secretr, token string) (string, error) {
	return v.TransitDecrypt(token)
}

type Plugin interface {
	Name() string
	Execute(input any) (any, error)
}

var plugins = make(map[string]Plugin)

// RegisterPlugin adds a new plugin.
func RegisterPlugin(p Plugin) error {
	if _, exists := plugins[p.Name()]; exists {
		return fmt.Errorf("plugin %s already registered", p.Name())
	}
	plugins[p.Name()] = p
	return nil
}

// ExecutePlugin calls the Execute method of a registered plugin.
func ExecutePlugin(name string, input any) (any, error) {
	if p, exists := plugins[name]; exists {
		return p.Execute(input)
	}
	return nil, fmt.Errorf("plugin %s not found", name)
}
