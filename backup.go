package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ExportVault returns a JSON formatted export of the vault data.
func ExportVault(v *Vault) (string, error) {
	export := struct {
		Data      map[string]any `json:"data"`
		Timestamp time.Time      `json:"timestamp"`
	}{
		Data:      v.data,
		Timestamp: time.Now(),
	}
	b, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ImportVault imports vault data from a JSON string.
func ImportVault(v *Vault, jsonData string) error {
	var imp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonData), &imp); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.data = imp.Data
	return v.save()
}

// BackupVault creates a backup file containing the vault export.
func BackupVault(v *Vault) error {
	backupDir := filepath.Join(vaultDir, "backups")
	os.MkdirAll(backupDir, 0700)
	exp, err := ExportVault(v)
	if err != nil {
		return err
	}
	filename := filepath.Join(backupDir, fmt.Sprintf("backup_%d.json", time.Now().Unix()))
	return os.WriteFile(filename, []byte(exp), 0600)
}
