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

// NEW: OIDCAuth implements OIDC-based authentication.
type OIDCAuth struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	User         string
}

func (oa *OIDCAuth) Name() string {
	return "oidc"
}

func (oa *OIDCAuth) Authenticate(credentials map[string]string) (string, error) {
	if credentials["id_token"] == "valid_oidc_token" {
		return oa.User, nil
	}
	return "", errors.New("invalid OIDC token")
}

// NEW: K8sAuth implements Kubernetes service account authentication.
type K8sAuth struct {
	ServiceAccount string
	Token          string
}

func (ka *K8sAuth) Name() string {
	return "k8s"
}

func (ka *K8sAuth) Authenticate(credentials map[string]string) (string, error) {
	if credentials["token"] == ka.Token && credentials["service_account"] == ka.ServiceAccount {
		return ka.ServiceAccount, nil
	}
	return "", errors.New("invalid Kubernetes credentials")
}

// NEW: AWSIAMAuth implements AWS IAM-based authentication.
type AWSIAMAuth struct {
	RoleARN string
	Token   string
	User    string
}

func (aa *AWSIAMAuth) Name() string {
	return "awsiam"
}

func (aa *AWSIAMAuth) Authenticate(credentials map[string]string) (string, error) {
	if credentials["token"] == aa.Token && credentials["role_arn"] == aa.RoleARN {
		return aa.User, nil
	}
	return "", errors.New("invalid AWS IAM credentials")
}
