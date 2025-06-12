package secretr

import (
	"errors"
	"fmt"
	"sync"
)

// Auth represents a pluggable authentication method.
type Auth interface {
	Name() string
	Authenticate(credentials map[string]string) (string, error)
}

// TokenAuth implements static token authentication via config.
type TokenAuth struct {
	Token string
	User  string
}

func (ta *TokenAuth) Name() string { return "token" }
func (ta *TokenAuth) Authenticate(credentials map[string]string) (string, error) {
	provided, ok := credentials["token"]
	if !ok {
		return "", errors.New("token not provided")
	}
	if provided != ta.Token {
		return "", errors.New("invalid token")
	}
	return ta.User, nil
}

// AppRoleAuth implements Vault AppRole authentication via Vault API.
type AppRoleAuth struct {
	VaultAddress string
	RoleID       string
	SecretID     string
	UserField    string // JSON field in response that contains user id
}

func (aa *AppRoleAuth) Name() string { return "approle" }
func (aa *AppRoleAuth) Authenticate(credentials map[string]string) (string, error) {
	role, rOk := credentials["role_id"]
	secret, sOk := credentials["secret_id"]
	if !rOk || !sOk {
		return "", errors.New("rol e_id or secret_id missing")
	}
	if role != aa.RoleID || secret != aa.SecretID {
		return "", errors.New("invalid approle credentials")
	}
	// In production, exchange with Vault API here; stub returns user field
	return aa.UserField, nil
}

// Auth provider registry for managing authentication methods.
var (
	authRegistry   = make(map[string]Auth)
	authRegistryMu sync.RWMutex
)

// RegisterAuthProvider registers an Auth provider.
// Returns an error if a provider with the same name is already registered.
func RegisterAuthProvider(am Auth) error {
	authRegistryMu.Lock()
	defer authRegistryMu.Unlock()
	name := am.Name()
	if _, exists := authRegistry[name]; exists {
		return fmt.Errorf("auth method provider %s already registered", name)
	}
	authRegistry[name] = am
	return nil
}

// UnregisterAuthProvider removes an Auth provider by name.
func UnregisterAuthProvider(name string) error {
	authRegistryMu.Lock()
	defer authRegistryMu.Unlock()
	if _, exists := authRegistry[name]; !exists {
		return fmt.Errorf("auth method provider %s not found", name)
	}
	delete(authRegistry, name)
	return nil
}

// GetAuthProvider retrieves an Auth provider by name.
func GetAuthProvider(name string) (Auth, error) {
	authRegistryMu.RLock()
	defer authRegistryMu.RUnlock()
	am, exists := authRegistry[name]
	if !exists {
		return nil, fmt.Errorf("auth method provider %s not registered", name)
	}
	return am, nil
}

// ListAuthProviders returns a slice of names of all registered auth method providers.
func ListAuthProviders() []string {
	authRegistryMu.RLock()
	defer authRegistryMu.RUnlock()
	names := make([]string, 0, len(authRegistry))
	for name := range authRegistry {
		names = append(names, name)
	}
	return names
}

// AuthenticateUser tries methods in order and returns first success or error.
func AuthenticateUser(auths []Auth, credentials map[string]string) (string, error) {
	for _, auth := range auths {
		user, err := auth.Authenticate(credentials)
		if err == nil {
			return user, nil
		}
	}
	return "", errors.New("authentication failed for all methods")
}
