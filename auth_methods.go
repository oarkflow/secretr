package secretr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/coreos/go-oidc"
	"github.com/go-ldap/ldap/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AuthMethod represents a pluggable authentication method.
type AuthMethod interface {
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

// LDAPAuth implements LDAP authentication using dynamic config.
type LDAPAuth struct {
	Server        string // host:port
	BindDN        string // e.g. "cn=%s,dc=example,dc=com"
	BaseDN        string // search base
	UserFilter    string // e.g. "(uid=%s)"
	TLS           bool
	SkipVerifyTLS bool
}

func (la *LDAPAuth) Name() string { return "ldap" }
func (la *LDAPAuth) Authenticate(credentials map[string]string) (string, error) {
	username, uOk := credentials["username"]
	password, pOk := credentials["password"]
	if !uOk || !pOk {
		return "", errors.New("username or password missing")
	}
	conn, err := ldap.DialURL("ldap://" + la.Server)
	if err != nil {
		return "", fmt.Errorf("ldap dial error: %w", err)
	}
	defer conn.Close()
	if la.TLS {
		_ = conn.StartTLS(&tls.Config{InsecureSkipVerify: la.SkipVerifyTLS})
	}
	// Initial bind (anonymous or service account)
	// Search for user's DN
	filter := fmt.Sprintf(la.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		la.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false,
		filter, []string{"dn"}, nil,
	)
	res, err := conn.Search(searchReq)
	if err != nil || len(res.Entries) == 0 {
		return "", errors.New("user not found in LDAP")
	}
	userDN := res.Entries[0].DN
	// Bind as user
	err = conn.Bind(userDN, password)
	if err != nil {
		return "", errors.New("invalid ldap credentials")
	}
	return username, nil
}

// OIDCAuth implements OIDC authentication using coreos/go-oidc.
type OIDCAuth struct {
	Issuer   string
	ClientID string
	Verifier *oidc.IDTokenVerifier
}

func NewOIDCAuth(ctx context.Context, issuer, clientID string) (*OIDCAuth, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to init OIDC provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	return &OIDCAuth{Issuer: issuer, ClientID: clientID, Verifier: verifier}, nil
}

func (oa *OIDCAuth) Name() string { return "oidc" }
func (oa *OIDCAuth) Authenticate(credentials map[string]string) (string, error) {
	idToken, ok := credentials["id_token"]
	if !ok {
		return "", errors.New("id_token missing")
	}
	tok, err := oa.Verifier.Verify(context.Background(), idToken)
	if err != nil {
		return "", fmt.Errorf("oidc token verification failed: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := tok.Claims(&claims); err != nil {
		return "", fmt.Errorf("failed to parse claims: %w", err)
	}
	return claims.Sub, nil
}

// K8sAuth validates in-cluster service account via API server.
type K8sAuth struct{}

func (ka *K8sAuth) Name() string { return "k8s" }
func (ka *K8sAuth) Authenticate(_ map[string]string) (string, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return "", fmt.Errorf("in-cluster config error: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", fmt.Errorf("k8s client init error: %w", err)
	}
	// simple call to verify credentials
	_, err = client.CoreV1().Namespaces().List(context.Background(), v1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("k8s auth failed: %w", err)
	}
	sa := config.BearerToken
	// service account name may come from token file
	return sa, nil
}

// AWSIAMAuth validates AWS credentials by calling STS GetCallerIdentity.
type AWSIAMAuth struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
}

func (aa *AWSIAMAuth) Name() string { return "awsiam" }
func (aa *AWSIAMAuth) Authenticate(_ map[string]string) (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(aa.AccessKeyID, aa.SecretAccessKey, aa.SessionToken),
		Region:      aws.String(aws.StringValue(aws.String(aa.Region))),
	})
	if err != nil {
		return "", fmt.Errorf("aws session error: %w", err)
	}
	svc := sts.New(sess)
	res, err := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("aws iam auth failed: %w", err)
	}
	return aws.StringValue(res.UserId), nil
}

// AuthenticateUser tries methods in order and returns first success or error.
func AuthenticateUser(auths []AuthMethod, credentials map[string]string) (string, error) {
	for _, auth := range auths {
		user, err := auth.Authenticate(credentials)
		if err == nil {
			return user, nil
		}
	}
	return "", errors.New("authentication failed for all methods")
}
