package secretr

import (
	"fmt"
	"time"
)

// GenerateDBCredential simulates on-the-fly generation of database credentials.
// NIST SP 800-57: These are ephemeral credentials, not cryptographic keys.
func GenerateDBCredential(engine string) (map[string]string, error) {
	// For demonstration we only support "postgres" and "mysql".
	var userPrefix string
	switch engine {
	case "postgres":
		userPrefix = "pguser"
	case "mysql":
		userPrefix = "myuser"
	default:
		return nil, fmt.Errorf("unsupported database engine")
	}
	user := fmt.Sprintf("%s_%s", userPrefix, GenerateRandomString(8))
	pass := GenerateRandomString(16)
	expiry := time.Now().Add(5 * time.Minute).Format(time.RFC3339)
	return map[string]string{
		"user":    user,
		"pass":    pass,
		"expires": expiry,
	}, nil
}

// GenerateCloudToken simulates generating a token for a cloud provider.
// NIST SP 800-57: These are ephemeral tokens, not cryptographic keys.
func GenerateCloudToken(provider string) (string, error) {
	// Supports "aws", "azure" and "gcp".
	var prefix string
	switch provider {
	case "aws":
		prefix = "aws-token"
	case "azure":
		prefix = "azure-token"
	case "gcp":
		prefix = "gcp-token"
	default:
		return "", fmt.Errorf("unsupported cloud provider")
	}
	token := fmt.Sprintf("%s-%s", prefix, GenerateRandomString(20))
	return token, nil
}

// WrapResponse encrypts sensitive data into a one‑time wrapping token.
// For simplicity, we reuse TransitEncrypt.
func WrapResponse(v *Secretr, data string) (string, error) {
	encrypted, err := v.TransitEncrypt(data)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

// UnwrapResponse returns the original data from a wrapping token.
func UnwrapResponse(v *Secretr, token string) (string, error) {
	return v.TransitDecrypt(token)
}

type Plugin interface {
	Name() string
	Execute(input any) (any, error)
}

var plugins = make(map[string]Plugin)

// RegisterPlugin adds a new plugin.
func RegisterPlugin(p Plugin) error {
	if _, exists := plugins[p.Name()]; exists {
		return fmt.Errorf("plugin %s already registered", p.Name())
	}
	plugins[p.Name()] = p
	return nil
}

// ExecutePlugin calls the Execute method of a registered plugin.
func ExecutePlugin(name string, input any) (any, error) {
	if p, exists := plugins[name]; exists {
		return p.Execute(input)
	}
	return nil, fmt.Errorf("plugin %s not found", name)
}
