package secretr

import (
	"fmt"
	"sync"
)

// Namespace represents a logical partition of the vault.
type Namespace struct {
	Name     string
	Policies map[string][]string // Maps user IDs to allowed actions.
	Data     map[string]any      // Isolated secret storage.
}

var (
	namespaces = make(map[string]*Namespace)
	nsMu       sync.Mutex
)

// CreateNamespace creates a new namespace.
func CreateNamespace(name string) error {
	nsMu.Lock()
	defer nsMu.Unlock()
	if _, exists := namespaces[name]; exists {
		return fmt.Errorf("namespace %s already exists", name)
	}
	namespaces[name] = &Namespace{
		Name:     name,
		Policies: make(map[string][]string),
		Data:     make(map[string]any),
	}
	return nil
}

// GetNamespace retrieves an existing namespace.
func GetNamespace(name string) (*Namespace, error) {
	nsMu.Lock()
	defer nsMu.Unlock()
	ns, exists := namespaces[name]
	if !exists {
		return nil, fmt.Errorf("namespace %s not found", name)
	}
	return ns, nil
}
