package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/secretr"
)

type Aws struct {
	Client string `json:"client,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type DummyPlugin struct{}

func (d DummyPlugin) Name() string {
	return "dummy"
}
func (d DummyPlugin) Execute(input any) (any, error) {
	return fmt.Sprintf("Processed: %v", input), nil
}

func exampleAuthMethods() {
	// OIDC example:
	oidcAuth, err := secretr.NewOIDCAuth(context.Background(), "https://accounts.example.com", "client123")
	if err != nil {
		fmt.Println("OIDCAuth init error:", err)
	} else {
		user, err := oidcAuth.Authenticate(map[string]string{"id_token": "valid_oidc_token"})
		if err != nil {
			fmt.Println("OIDCAuth error:", err)
		} else {
			fmt.Println("OIDCAuth authenticated user:", user)
		}
	}

	// Kubernetes auth example:
	k8s := &secretr.K8sAuth{}
	user, err := k8s.Authenticate(map[string]string{})
	if err != nil {
		fmt.Println("K8sAuth error:", err)
	} else {
		fmt.Println("K8sAuth authenticated service account token:", user)
	}

	// AWS IAM auth example:
	awsiam := &secretr.AWSIAMAuth{
		AccessKeyID:     "your_access_key_id",
		SecretAccessKey: "your_secret_access_key",
		SessionToken:    "",
	}
	user, err = awsiam.Authenticate(map[string]string{})
	if err != nil {
		fmt.Println("AWSIAMAuth error:", err)
	} else {
		fmt.Println("AWSIAMAuth authenticated user:", user)
	}
}

func main() {
	os.Setenv("SECRETR_MASTERKEY", "test1234")
	os.Setenv("SECRETR_KEY", secretr.GenerateRandomString())

	// Retrieve some existing secrets (if set)
	openAIKey, err := secretr.Get("OPENAI_KEY")
	if err != nil {
		panic(err)
	}
	deepSeekKey, err := secretr.Get("DEEPSEEK_KEY")
	if err != nil {
		panic(err)
	}
	fmt.Println("OPENAI_KEY  =", openAIKey)
	fmt.Println("DEEPSEEK_KEY =", deepSeekKey)
	// --- Dynamic Secrets ---
	dynamicSecret, err := secretr.GenerateDynamicSecret("temp_db_user", 5*time.Minute)
	if err != nil {
		panic(err)
	}
	fmt.Println("Dynamic secret for temp_db_user:", dynamicSecret)

	// --- Transit Encryption as a Service ---
	plaintext := "my sensitive data"
	encrypted, err := secretr.TransitEncrypt(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Transit Encrypted:", encrypted)
	decrypted, err := secretr.TransitDecrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println("Transit Decrypted:", decrypted)

	// --- Database Credentials Engine ---
	creds, err := secretr.GenerateDBCredential("postgres")
	if err != nil {
		panic(err)
	}
	fmt.Println("DB Credentials:", creds)

	// --- Cloud Provider Credentials Engine ---
	cloudToken, err := secretr.GenerateCloudToken("aws")
	if err != nil {
		panic(err)
	}
	fmt.Println("Cloud Token:", cloudToken)

	// --- Static (KV) Secrets Engine with Versioning ---
	// Set an initial KV secret.
	if err := secretr.Set("api_key", "initialKey"); err != nil {
		panic(err)
	}
	// Simulate a new version by generating a dynamic secret attached to the same key.
	versionedSecret, err := secretr.GenerateDynamicSecret("api_key", 10*time.Minute)
	if err != nil {
		panic(err)
	}
	fmt.Println("New dynamic version for api_key:", versionedSecret)
	versions, err := secretr.ListKVSecretVersions("api_key")
	if err != nil {
		panic(err)
	}
	fmt.Println("KV Versions for api_key:", versions)
	// Rollback to the initial version (version index 0).
	if err := secretr.RollbackKVSecret("api_key", 0); err != nil {
		panic(err)
	}
	rolledBack, err := secretr.Get("api_key")
	if err != nil {
		panic(err)
	}
	fmt.Println("Rollback KV api_key:", rolledBack)

	// --- Identity & Access Management ---
	allowed := secretr.CheckPolicy("admin", "*", "delete")
	fmt.Println("Admin allowed to delete any resource:", allowed)

	// --- Auth Methods Example ---
	// Using Token-based authentication.
	tokenAuth := &secretr.TokenAuth{
		Token: "secret-token",
		User:  "user123",
	}
	user, err := tokenAuth.Authenticate(map[string]string{"token": "secret-token"})
	if err != nil {
		panic(err)
	}
	fmt.Println("TokenAuth authenticated user:", user)

	// --- Response Wrapping ---
	wrapped, err := secretr.WrapResponse(secretr.Default(), "wrapped secret data")
	if err != nil {
		panic(err)
	}
	fmt.Println("Wrapped token:", wrapped)
	unwrapped, err := secretr.UnwrapResponse(secretr.Default(), wrapped)
	if err != nil {
		panic(err)
	}
	fmt.Println("Unwrapped data:", unwrapped)

	// --- Namespaces ---
	err = secretr.CreateNamespace("tenant1")
	if err != nil {
		fmt.Println("Namespace creation (or already exists):", err)
	}
	ns, err := secretr.GetNamespace("tenant1")
	if err != nil {
		panic(err)
	}
	fmt.Println("Namespace tenant1:", ns)

	// --- Plugins & Extensibility ---
	// Define and register a dummy plugin.

	if err := secretr.RegisterPlugin(DummyPlugin{}); err != nil {
		panic(err)
	}
	pluginOut, err := secretr.ExecutePlugin("dummy", "test input")
	if err != nil {
		panic(err)
	}
	fmt.Println("Plugin output:", pluginOut)

	// --- Multi-Region Replication ---
	// Replicate a backup to a regional directory.
	if err := secretr.ReplicateBackup(secretr.Default(), "./region_backup"); err != nil {
		fmt.Println("Backup replication error:", err)
	} else {
		fmt.Println("Backup replicated successfully")
	}

	// Example for HMAC Signing and Verification using SignData and VerifySignature:
	// First, set a key to be used as the HMAC key.
	secretHMACKey := "my_hmac_secret"
	if err := secretr.Set("hmac_key", secretHMACKey); err != nil {
		panic(err)
	}
	dataToSign := "important message"
	signature, err := secretr.SignData("hmac_key", dataToSign)
	if err != nil {
		panic(err)
	}
	fmt.Println("Data Signature:", signature)
	valid, err := secretr.VerifySignature("hmac_key", dataToSign, signature)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature valid?", valid)

	// Example for Hash Generation:
	hash, err := secretr.GenerateHash("The quick brown fox jumps over the lazy dog")
	if err != nil {
		panic(err)
	}
	fmt.Println("SHA-256 Hash:", hash)

	// Example for environment variable setting via Env:
	if err := secretr.Env("api_key"); err != nil {
		fmt.Println("Env error:", err)
	} else {
		fmt.Println("Environment variable 'api_key' is set.")
	}

	// Example for SSH Key Generation:
	if err := secretr.GenerateSSHKey("my_ssh_key"); err != nil {
		fmt.Println("SSH Key generation error:", err)
	} else {
		sshKeyData, err := secretr.Get("ssh-key:my_ssh_key")
		if err == nil {
			fmt.Println("SSH Key generated. (Private key stored securely)")
		}
		fmt.Println(sshKeyData)
	}

	// Example for Certificate Generation:
	if err := secretr.GenerateCertificate("my_cert", 30*24*time.Hour); err != nil {
		fmt.Println("Certificate generation error:", err)
	} else {
		certData, err := secretr.Get("certificate:my_cert")
		if err == nil {
			fmt.Println("Certificate generated successfully.")
		}
		fmt.Println(certData)
	}

	// End of examples.
	fmt.Println("All additional examples executed successfully.")

	// Additional examples for new auth methods:
	exampleAuthMethods()
}
