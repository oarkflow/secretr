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

func Copy(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Copy(key)
}

func Delete(key string) error {
	if defaultSecretr == nil {
		return fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Delete(key)
}

// Get retrieves the value associated with the provided key.
func Get(key string) (string, error) {
	if defaultSecretr == nil {
		return "", fmt.Errorf("secretr not initialized")
	}
	return defaultSecretr.Get(key)
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
