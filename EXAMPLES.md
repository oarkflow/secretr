# Secretr Usage Examples

Below are examples covering major features of the vault system.

## 1. Dynamic Secrets
Generate a dynamic secret (e.g., a database credential) with a lease.
```go
package main

import (
	"fmt"
	"time"

	"github.com/oarkflow/secretr"
)

func main() {
	v := secretr.New()
	// Assuming master prompt was handled (or use env master key)
	dyn, err := v.GenerateDynamicSecret("db_user", 5*time.Minute)
	if err != nil {
		panic(err)
	}
	fmt.Println("Dynamic secret for db_user:", dyn)
}
```

## 2. Static (Key/Value) Secrets Engine with Versioning
Store, retrieve, list versions and roll back a secret.
```go
package main

import (
	"fmt"
	"time"

	"github.com/oarkflow/secretr"
)

func main() {
	v := secretr.New()
	// Set a static secret
	if err := v.Set("api_key", "first-1234"); err != nil {
		panic(err)
	}
	// Update static secret to create version history
	if err := v.Set("api_key", "second-5678"); err != nil {
		panic(err)
	}
	// List all versions
	versions, err := v.ListKVSecretVersions("api_key")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Versions for 'api_key': %+v\n", versions)
	// Rollback to the first version (index 0)
	if err := v.RollbackKVSecret("api_key", 0); err != nil {
		panic(err)
	}
	// Get the rolled back secret
	secret, _ := v.Get("api_key")
	fmt.Println("Rolled back 'api_key':", secret)
}
```

## 3. Transit Engine – Encrypt/Decrypt and Sign/Verify
```go
package main

import (
	"fmt"

	"github.com/oarkflow/secretr"
)

func main() {
	v := secretr.New()
	plaintext := "Sensitive data to protect"

	// Encrypt
	encrypted, err := v.TransitEncrypt(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", encrypted)

	// Decrypt
	decrypted, err := v.TransitDecrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted:", decrypted)

	// Sign
	// Assume we have a secret stored under key "hmac_key"
	_ = v.Set("hmac_key", "supersecret")
	signature, err := v.SignData("hmac_key", plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature:", signature)

	// Verify
	valid, err := v.VerifySignature("hmac_key", plaintext, signature)
	if err != nil {
		panic(err)
	}
	fmt.Println("Signature valid:", valid)
}
```

## 4. Auth Methods – Example with OIDC
```go
package main

import (
	"fmt"

	"github.com/oarkflow/secretr"
)

func main() {
	// Using OIDC auth example
	oidc := secretr.OIDCAuth{
		Issuer:       "https://issuer.example.com",
		ClientID:     "client123",
		ClientSecret: "secretXYZ",
		User:         "user@example.com",
	}
	creds := map[string]string{"id_token": "valid_oidc_token"}
	user, err := oidc.Authenticate(creds)
	if err != nil {
		fmt.Println("OIDC auth failed:", err)
	} else {
		fmt.Println("OIDC authenticated user:", user)
	}
}
```

## 5. Namespaces for Multi‑Tenant Isolation
```go
package main

import (
	"fmt"

	"github.com/oarkflow/secretr"
)

func main() {
	// Create a new namespace
	if err := secretr.CreateNamespace("tenantA"); err != nil {
		panic(err)
	}
	ns, err := secretr.GetNamespace("tenantA")
	if err != nil {
		panic(err)
	}
	fmt.Println("Namespace created:", ns.Name)
	// Store secrets separately in each namespace (example concept)
}
```

## 6. Audit Logging
Every secret operation automatically logs an audit trail.
```go
// No extra code needed—audit is performed inside functions like Set, Delete, etc.
// Check your audit log file under ~/.secretr/audit-YYYY-MM-DD.log for entries.
```

## 7. Multi‑Region Replication & Backup
```go
package main

import (
	"fmt"

	"github.com/oarkflow/secretr"
)

func main() {
	v := secretr.New()
	// Create a backup in the default backups folder.
	if err := secretr.BackupSecretr(v); err != nil {
		panic(err)
	}
	// Replicate to another regional directory:
	regionDir := "/Users/sujit/Sites/secretr/backups/region-us-west"
	if err := secretr.ReplicateBackup(v, regionDir); err != nil {
		panic(err)
	}
	fmt.Println("Backup and replication completed")
}
```

## 8. TLS Termination & Proxying (API)
Run the HTTP/HTTPS API server with TLS configuration.
```go
package main

import (
	"github.com/oarkflow/secretr"
)

func main() {
	v := secretr.New()
	// Set environment variables SECRETR_CERT and SECRETR_KEY with certificate file paths.
	// The server will automatically serve HTTPS if these variables are set.
	secretr.StartSecureHTTPServer(v)
}
```

## 9. Plugins & Extensibility
Call your registered plugin via the engine.
```go
package main

import (
	"fmt"

	"github.com/oarkflow/secretr"
)

func main() {
	// Execute the example plugin registered in main.go
	result, err := secretr.ExecutePlugin("example-plugin", "sample input")
	if err != nil {
		fmt.Println("Plugin error:", err)
	} else {
		fmt.Println(result)
	}
}
```

Save and run each example to see the vault system in action.
