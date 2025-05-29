package drivers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// FileStorage implements the Storage interface by storing shares in individual files.
type FileStorage struct {
	dir string
	mu  sync.RWMutex
}

// NewFileStorage creates a new FileStorage in the given directory.
// The directory is created if it does not exist.
func NewFileStorage(dir string) (*FileStorage, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &FileStorage{dir: dir}, nil
}

// fileName returns the full path for a given share index.
func (fs *FileStorage) fileName(index byte) string {
	return filepath.Join(fs.dir, fmt.Sprintf("share_%d.dat", index))
}

// SetShare writes the share to a file.
func (fs *FileStorage) SetShare(index byte, share []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return os.WriteFile(fs.fileName(index), share, 0600)
}

// GetShare reads the share from its file.
func (fs *FileStorage) GetShare(index byte) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	data, err := os.ReadFile(fs.fileName(index))
	if err != nil {
		return nil, errors.New("filestorage: share not found")
	}
	return data, nil
}

// ListShares returns indices from the files found in the storage directory.
func (fs *FileStorage) ListShares() ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	files, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, err
	}
	var indices []byte
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "share_") && strings.HasSuffix(file.Name(), ".dat") {
			parts := strings.Split(strings.TrimSuffix(file.Name(), ".dat"), "_")
			if len(parts) != 2 {
				continue
			}
			i, err := strconv.Atoi(parts[1])
			if err != nil {
				continue
			}
			indices = append(indices, byte(i))
		}
	}
	return indices, nil
}
