package secretr

import (
	"fmt"
	"log"
	"time"
)

func Set(key string, value any) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Set(key, value)
}

func MustSet(key string, value any) {
	if defaultSecretr == nil {
		log.Fatal("secretr not initialized")
	}
	if err := defaultSecretr.Set(key, value); err != nil {
		log.Fatalf("failed to set key %s: %v", key, err)
	}
}

func Copy(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Copy(key)
}

func MustCopy(key string) {
	if defaultSecretr == nil {
		log.Fatal("secretr not initialized")
	}
	if err := defaultSecretr.Copy(key); err != nil {
		log.Fatalf("failed to copy key %s: %v", key, err)
	}
}

func Delete(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Delete(key)
}

func MustDelete(key string) {
	if defaultSecretr == nil {
		log.Fatal("secretr not initialized")
	}
	if err := defaultSecretr.Delete(key); err != nil {
		log.Fatalf("failed to delete key %s: %v", key, err)
	}
}

// Get retrieves the value associated with the provided key.
func Get(key string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Get(key)
}

// List retrieves the value associated with the provided key.
func List() ([]string, error) {
	if defaultSecretr == nil {
		return nil, fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.List(), nil
}

func MustGet(key string) string {
	if defaultSecretr == nil {
		log.Fatal("secretr not initialized")
	}
	value, err := defaultSecretr.Get(key)
	if err != nil {
		log.Fatalf("failed to get key %s: %v", key, err)
	}
	return value
}

func Unmarshal(key string, dest any) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Unmarshal(key, dest)
}

// LoadFromEnv loads environment variables into the secretr.
func LoadFromEnv() {
	if defaultSecretr == nil {
		log.Fatal("secretr not initialized")
	}
	defaultSecretr.LoadFromEnv()
}

func GenerateDynamicSecret(name string, leaseDuration time.Duration) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.GenerateDynamicSecret(name, leaseDuration)
}

func VerifyDynamicSecret(name, secret string) (bool, error) {
	if defaultSecretr == nil {
		return false, fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.VerifyDynamicSecret(name, secret)
}

func TransitEncrypt(plaintext string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.TransitEncrypt(plaintext)
}

func TransitDecrypt(encText string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.TransitDecrypt(encText)
}

func ListKVSecretVersions(val string) ([]SecretMeta, error) {
	if defaultSecretr == nil {
		return nil, fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.ListKVSecretVersions(val)
}

func RollbackKVSecret(key string, versionIndex int) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.RollbackKVSecret(key, versionIndex)
}

func SignData(key string, data string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.SignData(key, data)
}

func VerifySignature(key string, data string, signature string) (bool, error) {
	if defaultSecretr == nil {
		return false, fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.VerifySignature(key, data, signature)
}

func GenerateHash(data string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.GenerateHash(data), nil
}

func Env(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Env(key)
}

func EnrichEnv() error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.EnrichEnv()
}

func GenerateSSHKey(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.GenerateSSHKey(key)
}

func GenerateCertificate(key string, dur time.Duration) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.GenerateCertificate(key, dur)
}
