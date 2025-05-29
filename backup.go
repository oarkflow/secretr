package secretr

import (
	"encoding/json"
	"fmt"
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

// ImportSecretr imports secretr data from a JSON string.
func ImportSecretr(v *Secretr, jsonData string) error {
	var imp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonData), &imp); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.store.Data = imp.Data
	return v.Save()
}

// BackupSecretr creates a backup file containing the secretr export.
func BackupSecretr(v *Secretr) error {
	backupDir := filepath.Join(secretrDir, "backups")
	os.MkdirAll(backupDir, 0700)
	exp, err := ExportSecretr(v)
	if err != nil {
		return err
	}
	filename := filepath.Join(backupDir, fmt.Sprintf("backup_%d.json", time.Now().Unix()))
	return os.WriteFile(filename, []byte(exp), 0600)
}

// ReplicateBackup creates a backup in a specified regional directory.
func ReplicateBackup(v *Secretr, regionDir string) error {
	exp, err := ExportSecretr(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(regionDir, 0700); err != nil {
		return err
	}
	filename := filepath.Join(regionDir, fmt.Sprintf("backup_%d.json", time.Now().Unix()))
	return os.WriteFile(filename, []byte(exp), 0600)
}
