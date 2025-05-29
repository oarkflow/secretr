package secretr

import "errors"

// AuthMethod represents a pluggable authentication method.
type AuthMethod interface {
	Name() string
	Authenticate(credentials map[string]string) (string, error) // returns authenticated user ID
}

// TokenAuth implements token-based authentication.
type TokenAuth struct {
	Token string
	User  string
}

func (ta *TokenAuth) Name() string {
	return "token"
}
func (ta *TokenAuth) Authenticate(credentials map[string]string) (string, error) {
	provided, ok := credentials["token"]
	if !ok || provided != ta.Token {
		return "", errors.New("invalid token")
	}
	return ta.User, nil
}

// AppRoleAuth implements AppRole-based authentication.
type AppRoleAuth struct {
	RoleID   string
	SecretID string
	User     string
}

func (aa *AppRoleAuth) Name() string {
	return "approle"
}
func (aa *AppRoleAuth) Authenticate(credentials map[string]string) (string, error) {
	role, rOk := credentials["role_id"]
	secret, sOk := credentials["secret_id"]
	if !rOk || !sOk || role != aa.RoleID || secret != aa.SecretID {
		return "", errors.New("invalid approle credentials")
	}
	return aa.User, nil
}

// LDAPAuth implements a simple LDAP-like authentication.
type LDAPAuth struct {
	Username string
	Password string
}

func (la *LDAPAuth) Name() string {
	return "ldap"
}
func (la *LDAPAuth) Authenticate(credentials map[string]string) (string, error) {
	user, uOk := credentials["username"]
	pass, pOk := credentials["password"]
	if !uOk || !pOk || user != la.Username || pass != la.Password {
		return "", errors.New("invalid ldap credentials")
	}
	return user, nil
}
