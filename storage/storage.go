package storage

import (
	"errors"
	"sync"
)

// Storage defines an interface for storing and retrieving key shares.
type IStorage interface {
	SetShare(index byte, share []byte) error
	GetShare(index byte) ([]byte, error)
	// List all stored share indices
	ListShares() ([]byte, error)
}

// Storage allows different storage backends per share index.
type Storage struct {
	mu       sync.RWMutex
	storages map[byte]IStorage
}

// New returns a new Storage instance.
func New() *Storage {
	return &Storage{storages: make(map[byte]IStorage)}
}

// AssignStorage assigns a specific storage backend for a share index.
func (ms *Storage) AssignStorage(index byte, storage IStorage) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.storages[index] = storage
}

// SetShare stores a share in its designated storage backend.
func (ms *Storage) SetShare(index byte, share []byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	storage, ok := ms.storages[index]
	if !ok {
		return errors.New("shamir: no storage assigned for share index")
	}
	return storage.SetShare(index, share)
}

// GetShare retrieves a share from its designated storage backend.
func (ms *Storage) GetShare(index byte) ([]byte, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	storage, ok := ms.storages[index]
	if !ok {
		return nil, errors.New("shamir: no storage assigned for share index")
	}
	return storage.GetShare(index)
}

// ListShares lists all share indices that have assigned storage.
func (ms *Storage) ListShares() ([]byte, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	indices := make([]byte, 0, len(ms.storages))
	for idx := range ms.storages {
		indices = append(indices, idx)
	}
	return indices, nil
}

// StoreSharesMulti stores each given share into its respective storage backend.
func StoreSharesMulti(shares [][]byte, Storage *Storage) error {
	for _, share := range shares {
		index := share[0]
		if err := Storage.SetShare(index, share); err != nil {
			return err
		}
	}
	return nil
}

// RetrieveSharesMulti retrieves shares from their designated storage backends based on provided indices.
func RetrieveSharesMulti(indices []byte, Storage *Storage) ([][]byte, error) {
	var shares [][]byte
	for _, idx := range indices {
		share, err := Storage.GetShare(idx)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, nil
}
