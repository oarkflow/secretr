package main

import (
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

func main() {
	os.Setenv("SECRETR_MASTERKEY", "test1234")

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
	if err := secretr.ReplicateBackup(secretr.Default(), "/Users/sujit/Sites/secretr/region_backup"); err != nil {
		fmt.Println("Backup replication error:", err)
	} else {
		fmt.Println("Backup replicated successfully")
	}
}
