package vault

import (
	"os"
)

type StorageBackend interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

type FileStorage struct {
	path string
}

func NewFileStorage(path string) *FileStorage {
	return &FileStorage{path: path}
}

func (fs *FileStorage) Load() ([]byte, error) {
	return os.ReadFile(fs.path)
}

func (fs *FileStorage) Save(data []byte) error {
	return os.WriteFile(fs.path, data, 0600)
}

// Optionally add more methods (e.g. Backup) or alternative backends.
