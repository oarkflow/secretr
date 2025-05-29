package drivers

import (
	"errors"
	"sync"
)

// MemoryStorage implements a simple in-memory storage system.
type MemoryStorage struct {
	mu   sync.RWMutex
	data map[byte][]byte
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: make(map[byte][]byte)}
}

func (ms *MemoryStorage) SetShare(index byte, share []byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.data[index] = share
	return nil
}

func (ms *MemoryStorage) GetShare(index byte) ([]byte, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	share, ok := ms.data[index]
	if !ok {
		return nil, errors.New("shamir: share not found")
	}
	return share, nil
}

func (ms *MemoryStorage) ListShares() ([]byte, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	indices := make([]byte, 0, len(ms.data))
	for k := range ms.data {
		indices = append(indices, k)
	}
	return indices, nil
}
