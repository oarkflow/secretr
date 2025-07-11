package secretr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ExportSecretr returns a JSON formatted export of the secretr data.
func ExportSecretr(v *Secretr) (string, error) {
	export := struct {
		Data      map[string]any `json:"data"`
		Timestamp time.Time      `json:"timestamp"`
	}{
		Data:      v.store.Data,
		Timestamp: time.Now(),
	}
	b, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// getEncryptionKey retrieves the encryption key from environment variable SECRETR_KEY.
// NIST SP 800-57: The backup encryption key must be 32 bytes (AES-256).
// If not set, generate a random key and print a warning.
func getEncryptionKey() ([]byte, error) {
	keyStr := os.Getenv("SECRETR_KEY")
	if keyStr == "" {
		key, err := generateRandomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup key: %v", err)
		}
		fmt.Fprintln(os.Stderr, "WARNING: SECRETR_KEY not set, using random key for backup (not recoverable)")
		return key, nil
	}
	key := []byte(keyStr)
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}
	return key, nil
}

func encryptData(plaintext string, key []byte) (string, error) {
	// NIST SP 800-57: Use AES-GCM for backup encryption.
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
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptData(ciphertextEnc string, key []byte) (string, error) {
	// NIST SP 800-57: Use AES-GCM for backup decryption.
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextEnc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintextBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintextBytes), nil
}

// ImportSecretr imports secretr data from an encrypted JSON string.
func ImportSecretr(v *Secretr, encryptedData string) error {
	key, err := getEncryptionKey()
	if err != nil {
		return err
	}
	decData, err := decryptData(encryptedData, key)
	if err != nil {
		return err
	}
	var imp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(decData), &imp); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.store.Data = imp.Data
	return v.Save()
}

// BackupSecretr creates a backup file containing the secretr export (encrypted).
func BackupSecretr(v *Secretr) error {
	backupDir := filepath.Join(secretrDir, "backups")
	_ = os.MkdirAll(backupDir, 0700)
	exp, err := ExportSecretr(v)
	if err != nil {
		return err
	}
	key, err := getEncryptionKey()
	if err != nil {
		return err
	}
	encData, err := encryptData(exp, key)
	if err != nil {
		return err
	}
	filename := filepath.Join(backupDir, fmt.Sprintf("backup_%d.enc", time.Now().Unix()))
	return os.WriteFile(filename, []byte(encData), 0600)
}

// ReplicateBackup creates a backup file in the specified regional directory (encrypted).
func ReplicateBackup(v *Secretr, regionDir string) error {
	exp, err := ExportSecretr(v)
	if err != nil {
		return err
	}
	key, err := getEncryptionKey()
	if err != nil {
		return err
	}
	encData, err := encryptData(exp, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(regionDir, 0700); err != nil {
		return err
	}
	filename := filepath.Join(regionDir, fmt.Sprintf("backup_%d.enc", time.Now().Unix()))
	return os.WriteFile(filename, []byte(encData), 0600)
}

// BackupAllKeys creates a backup of all managed keys (metadata + encrypted material).
func BackupAllKeys() (string, error) {
	globalKeyStore.mu.Lock()
	defer globalKeyStore.mu.Unlock()
	b, err := json.MarshalIndent(globalKeyStore.Keys, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// RestoreAllKeys restores all managed keys from a backup (overwrites current).
func RestoreAllKeys(backup string) error {
	globalKeyStore.mu.Lock()
	defer globalKeyStore.mu.Unlock()
	var keys map[string][]ManagedKey
	if err := json.Unmarshal([]byte(backup), &keys); err != nil {
		return err
	}
	globalKeyStore.Keys = keys
	return nil
}

// ArchiveKeyVersion stores a specific key version in backup.
func ArchiveKeyVersion(keyID string, version int) error {
	globalKeyStore.mu.Lock()
	defer globalKeyStore.mu.Unlock()
	versions, ok := globalKeyStore.Keys[keyID]
	if !ok {
		return fmt.Errorf("key not found")
	}
	for i, k := range versions {
		if k.Metadata.Version == version {
			globalKeyStore.Backup[keyID] = append(globalKeyStore.Backup[keyID], k)
			// Remove from active keys
			globalKeyStore.Keys[keyID] = append(versions[:i], versions[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("version not found")
}
