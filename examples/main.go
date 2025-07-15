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

func exampleAllFunctions() {
	// Consolidated examples for all functions.
	// Set/Get
	if err := secretr.Set("example_key", "example_value"); err != nil {
		fmt.Println("Set error:", err)
	}
	val, err := secretr.Get("example_key")
	if err != nil {
		fmt.Println("Get error:", err)
	} else {
		fmt.Println("Get example_key:", val)
	}

	// Delete example
	if err := secretr.Delete("example_key"); err != nil {
		fmt.Println("Delete error:", err)
	} else {
		fmt.Println("Deleted example_key")
	}

	// Dynamic secret generation and validation.
	ds, err := secretr.GenerateDynamicSecret("dynamic_example", 2*time.Minute)
	if err != nil {
		fmt.Println("GenerateDynamicSecret error:", err)
	} else {
		fmt.Println("Dynamic secret for dynamic_example:", ds)
		valid, err := secretr.VerifyDynamicSecret("dynamic_example", ds)
		if err != nil {
			fmt.Println("VerifyDynamicSecret error:", err)
		} else {
			fmt.Println("Dynamic secret valid?", valid)
		}
	}

	// Transit encryption/decryption.
	encrypted, err := secretr.TransitEncrypt("sample text")
	if err != nil {
		fmt.Println("TransitEncrypt error:", err)
	} else {
		fmt.Println("TransitEncrypted text:", encrypted)
		dec, err := secretr.TransitDecrypt(encrypted)
		if err != nil {
			fmt.Println("TransitDecrypt error:", err)
		} else {
			fmt.Println("TransitDecrypted text:", dec)
		}
	}

	// KV secret versioning
	if err := secretr.Set("kv_example", "v1_initial"); err != nil {
		fmt.Println("Set kv_example error:", err)
	}
	_, err = secretr.GenerateDynamicSecret("kv_example", 5*time.Minute)
	if err != nil {
		fmt.Println("GenerateDynamicSecret for kv_example error:", err)
	}
	versions, err := secretr.ListKVSecretVersions("kv_example")
	if err != nil {
		fmt.Println("ListKVSecretVersions error:", err)
	} else {
		fmt.Println("KVSecret versions for kv_example:", versions)
		if len(versions) > 0 {
			if err := secretr.RollbackKVSecret("kv_example", 0); err != nil {
				fmt.Println("RollbackKVSecret error:", err)
			} else {
				updated, _ := secretr.Get("kv_example")
				fmt.Println("After rollback, kv_example:", updated)
			}
		}
	}

	// Environment variable handling.
	if err := secretr.Set("demo_env", "env_value"); err != nil {
		fmt.Println("Set demo_env error:", err)
	}
	if err := secretr.Env("demo_env"); err != nil {
		fmt.Println("Env error:", err)
	} else {
		fmt.Println("Environment variable 'demo_env' set to:", os.Getenv("demo_env"))
	}
	if err := secretr.EnrichEnv(); err != nil {
		fmt.Println("EnrichEnv error:", err)
	} else {
		fmt.Println("Enriched environment variables.")
	}

	// Database and Cloud Credential engines.
	dbCreds, err := secretr.GenerateDBCredential("postgres")
	if err != nil {
		fmt.Println("GenerateDBCredential error:", err)
	} else {
		fmt.Println("DB Credentials (postgres):", dbCreds)
	}
	cloudToken, err := secretr.GenerateCloudToken("aws")
	if err != nil {
		fmt.Println("GenerateCloudToken error:", err)
	} else {
		fmt.Println("Cloud Token (aws):", cloudToken)
	}

	// Response wrapping.
	wrapped, err := secretr.WrapResponse(secretr.Default(), "wrapped secret data")
	if err != nil {
		fmt.Println("WrapResponse error:", err)
	} else {
		fmt.Println("Wrapped response:", wrapped)
		unwrapped, err := secretr.UnwrapResponse(secretr.Default(), wrapped)
		if err != nil {
			fmt.Println("UnwrapResponse error:", err)
		} else {
			fmt.Println("Unwrapped response:", unwrapped)
		}
	}

	// Policy check (if implemented).
	allowed := secretr.CheckPolicy("admin", "*", "delete")
	fmt.Println("Policy check for admin deleting any resource:", allowed)
	allowed = secretr.CheckPolicy("user", "non_sensitive", "read")
	fmt.Println("Policy check for user reading non_sensitive:", allowed)
	allowed = secretr.CheckPolicy("user", "sensitive", "write")
	fmt.Println("Policy check for user writing sensitive resource:", allowed)

	// Plugin registration and execution.
	if err := secretr.RegisterPlugin(DummyPlugin{}); err != nil {
		fmt.Println("RegisterPlugin error:", err)
	}
	pluginOut, err := secretr.ExecutePlugin("dummy", "test plugin input")
	if err != nil {
		fmt.Println("ExecutePlugin error:", err)
	} else {
		fmt.Println("Plugin executed output:", pluginOut)
	}

	// Token authentication example.
	tokenAuth := &secretr.TokenAuth{Token: "secret-token", User: "user123"}
	userAuth, err := tokenAuth.Authenticate(map[string]string{"token": "secret-token"})
	if err != nil {
		fmt.Println("TokenAuth error:", err)
	} else {
		fmt.Println("TokenAuth authenticated user:", userAuth)
	}
}

func main() {
	os.Setenv("SECRETR_MASTERKEY", "test1234")
	os.Setenv("SECRETR_KEY", secretr.GenerateRandomString())

	// Store a file
	err := secretr.StoreFile("file.txt",
		[]string{"important", "confidential"},
		map[string]string{"department": "finance"})

	if err != nil {
		panic(err)
	}

	// Retrieve a file
	_, metadata, err := secretr.RetrieveFile("file.txt")
	if err != nil {
		panic(err)
	}
	// Use content and metadata
	fmt.Printf("File: %s, Size: %d, Created: %v\n",
		metadata.FileName, metadata.Size, metadata.CreatedAt.Format(time.DateTime))

	// List all files
	files := secretr.ListFiles()
	for _, f := range files {
		fmt.Printf("File: %s, Tags: %v\n", f.FileName, f.Tags)
	}
	return
	v := secretr.New()
	v.SetDistributeKey(false)
	err = v.PromptMaster()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(v.List())
	// Retrieve some existing secrets (if set).
	openAIKey := secretr.MustGet("OPENAI_KEY")
	deepSeekKey := secretr.MustGet("DEEPSEEK_KEY")
	fmt.Println("OPENAI_KEY  =", openAIKey)
	fmt.Println("DEEPSEEK_KEY =", deepSeekKey)

	// --- Managed Key Lifecycle Example ---
	fmt.Println("=== Managed Key Lifecycle Example ===")
	keyID := "demo-key"
	// Create AES-256 key for encryption
	mk, err := v.CreateManagedKey(keyID, secretr.KeyTypeAES256, "encrypt")
	if err != nil {
		fmt.Println("CreateManagedKey error:", err)
	} else {
		fmt.Printf("Created key: %+v\n", mk.Metadata)
	}
	// Rotate key
	mk2, err := v.RotateManagedKey(keyID)
	if err != nil {
		fmt.Println("RotateManagedKey error:", err)
	} else {
		fmt.Printf("Rotated key: %+v\n", mk2.Metadata)
	}
	// List keys
	keys := v.ListManagedKeys()
	fmt.Println("All managed keys:", keys)
	// Archive key
	if err := v.ArchiveManagedKey(keyID); err != nil {
		fmt.Println("ArchiveManagedKey error:", err)
	} else {
		fmt.Println("Archived key:", keyID)
	}
	// Restore key
	if err := v.RestoreManagedKey(keyID); err != nil {
		fmt.Println("RestoreManagedKey error:", err)
	} else {
		fmt.Println("Restored key:", keyID)
	}
	// Enforce usage policy
	if err := v.EnforceKeyUsage(keyID, "encrypt"); err != nil {
		fmt.Println("EnforceKeyUsage error:", err)
	} else {
		fmt.Println("Key usage policy enforcement passed for encrypt")
	}
	// Destroy key and audit
	if err := v.DestroyKeyAndAudit(keyID); err != nil {
		fmt.Println("DestroyKeyAndAudit error:", err)
	} else {
		fmt.Println("Destroyed key and audited:", keyID)
	}

	// Execute the consolidated example to demonstrate all functions.
	exampleAllFunctions()

	fmt.Println("All examples executed successfully.")
}
