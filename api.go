package secretr

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	rateLimit = 10
	limiter   = make(map[string]int)
	limMu     sync.Mutex

	userTokens = map[string]string{} // token -> username
	userDBMu   sync.RWMutex
)

// Load users from CSV file: username,token
func loadUserDB(path string) error {
	userDBMu.Lock()
	defer userDBMu.Unlock()

	userTokens = make(map[string]string) // Initialize the map

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	// Read the header row
	header, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("CSV file %s is empty", path)
		}
		return fmt.Errorf("failed to read CSV header from %s: %w", path, err)
	}

	// Find the indices of "username" and "token"
	usernameIndex := -1
	tokenIndex := -1
	for i, col := range header {
		trimmedCol := strings.TrimSpace(col)
		if trimmedCol == "username" {
			usernameIndex = i
		} else if trimmedCol == "token" {
			tokenIndex = i
		}
	}

	if usernameIndex == -1 || tokenIndex == -1 {
		return fmt.Errorf("CSV header in %s must contain 'username' and 'token' columns", path)
	}

	// Read the remaining rows
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break // End of file
		}
		if err != nil {
			return fmt.Errorf("failed to read CSV record from %s: %w", path, err)
		}

		// Ensure the record has enough columns before accessing
		if len(record) > usernameIndex && len(record) > tokenIndex {
			username := strings.TrimSpace(record[usernameIndex])
			token := strings.TrimSpace(record[tokenIndex])

			if username != "" && token != "" {
				userTokens[token] = username
			}
		} else {
			// Optionally log or handle malformed rows more specifically
			fmt.Printf("Warning: Skipping malformed row in %s: %v\n", path, record)
		}
	}

	fmt.Printf("Successfully loaded user data from %s. Total entries: %d\n", path, len(userTokens))
	// fmt.Println(userTokens) // Uncomment for debugging to see the map content
	return nil
}

// authMiddleware validates the Bearer token provided in the Authorization header.
func authMiddleware(next http.Handler) http.Handler {
	token := os.Getenv("SECRETR_TOKEN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware limits the number of requests per IP address.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limMu.Lock()
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		limiter[ip]++
		count := limiter[ip]
		limMu.Unlock()
		if count > rateLimit {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NEW: Transit engine endpoints.
func initTransitEndpoints(mux *http.ServeMux, v *Secretr) {
	mux.HandleFunc("/secretr/transit/encrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		encrypted, err := v.TransitEncrypt(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(encrypted))
		LogAudit("transit_encrypt", "", "encrypted data", v.masterKey)
	})
	mux.HandleFunc("/secretr/transit/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		decrypted, err := v.TransitDecrypt(string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(decrypted))
		LogAudit("transit_decrypt", "", "decrypted data", v.masterKey)
	})

	mux.Handle("/secretr/engine/db", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engine := r.URL.Query().Get("engine")
		if engine == "" {
			http.Error(w, "engine parameter required", http.StatusBadRequest)
			return
		}
		creds, err := GenerateDBCredential(engine)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(creds)
		LogAudit("db_engine", engine, "generated db credentials", v.masterKey)
	}))))

	// Cloud Provider Credentials engine
	mux.Handle("/secretr/engine/cloud", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			http.Error(w, "provider parameter required", http.StatusBadRequest)
			return
		}
		token, err := GenerateCloudToken(provider)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(token))
		LogAudit("cloud_engine", provider, "generated cloud token", v.masterKey)
	}))))

	// Response wrapping endpoints.
	mux.Handle("/secretr/wrap", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		token, err := WrapResponse(v, string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(token))
		LogAudit("wrap", "", "wrapped response", v.masterKey)
	}))))

	mux.Handle("/secretr/unwrap", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		plain, err := UnwrapResponse(v, string(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(plain))
		LogAudit("unwrap", "", "unwrapped response", v.masterKey)
	}))))

	// KV secret rollback endpoint.
	mux.Handle("/secretr/kv/rollback", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		verStr := r.URL.Query().Get("version")
		if key == "" || verStr == "" {
			http.Error(w, "key and version parameters required", http.StatusBadRequest)
			return
		}
		ver, err := strconv.Atoi(verStr)
		if err != nil {
			http.Error(w, "invalid version", http.StatusBadRequest)
			return
		}
		if err := v.RollbackKVSecret(key, ver); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		LogAudit("kv_rollback", key, fmt.Sprintf("rolled back to version %d", ver), v.masterKey)
	}))))

	mux.Handle("/secretr/", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		robustSecretrHTTPHandler(v, w, r)
	}))))

	// List all keys
	mux.Handle("/secretr/list", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := v.List()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keys)
	}))))

	// SSH key management
	mux.Handle("/secretr/ssh-key", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var req struct {
				Name       string `json:"name"`
				PrivateKey string `json:"private_key"`
				PublicKey  string `json:"public_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			v.store.SSHKeys[req.Name] = SSHKey{Private: req.PrivateKey, Public: req.PublicKey}
			if err := v.Save(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "Name is required", http.StatusBadRequest)
				return
			}
			res := v.store.SSHKeys[name]
			_ = json.NewEncoder(w).Encode(res)
		case http.MethodDelete:
			name := r.URL.Query().Get("name")
			delete(v.store.SSHKeys, name)
			_ = v.Save()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}))))

	// Certificate management
	mux.Handle("/secretr/certificate", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name     string `json:"name"`
			Duration int    `json:"duration"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := v.GenerateCertificate(req.Name, time.Duration(req.Duration)*time.Hour*24); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))))

	// Dynamic secret verification
	mux.Handle("/secretr/dynamic/verify", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name   string `json:"name"`
			Secret string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ok, err := v.VerifyDynamicSecret(req.Name, req.Secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"valid": ok})
	}))))

	// Export/Import
	mux.Handle("/secretr/export", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exp, err := ExportSecretr(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(exp))
	}))))

	mux.Handle("/secretr/import", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := ImportSecretr(v, string(body)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))))

	// Auth endpoint (for extensibility)
	mux.HandleFunc("/secretr/auth", func(w http.ResponseWriter, r *http.Request) {
		// In production, implement login and token issuance.
		http.Error(w, "Not implemented. Use your API key as Bearer token.", http.StatusNotImplemented)
	})

	mux.HandleFunc("/secretr/group", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Application string `json:"application"`
			Namespace   string `json:"namespace"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := v.AddGroup(req.Application, req.Namespace); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/secretr/secret", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Application string `json:"application"`
			Namespace   string `json:"namespace"`
			Duration    int    `json:"duration"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		secret, err := v.GenerateUniqueSecret(req.Application, req.Namespace, time.Duration(req.Duration)*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(secret))
	})
}

// userAuthMiddleware authenticates using a Bearer token and sets user in context.
func userAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		userDBMu.RLock()
		user, ok := userTokens[token]
		userDBMu.RUnlock()
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getUserFromRequest extracts the user from context.
func getUserFromRequest(r *http.Request) string {
	user, _ := r.Context().Value("user").(string)
	return user
}

// --- Enhanced secretr HTTP handler with JSON responses and access control ---

func robustSecretrHTTPHandler(v *Secretr, w http.ResponseWriter, r *http.Request) {
	user := getUserFromRequest(r)
	key := strings.TrimPrefix(r.URL.Path, "/secretr/")
	switch {
	case strings.HasPrefix(key, "dynamic/"):
		name := strings.TrimPrefix(key, "dynamic/")
		leaseStr := r.URL.Query().Get("lease")
		lease, err := time.ParseDuration(leaseStr + "s")
		if err != nil || lease <= 0 {
			lease = time.Minute * 10
		}
		secret, err := v.GenerateDynamicSecret(name, lease)
		if err != nil {
			http.Error(w, "failed to generate dynamic secret: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"secret": secret})
		LogAudit("dynamic", name, "generated dynamic secret", v.masterKey)
		return
	case key == "" || key == "keys":
		keys := v.List()
		_ = json.NewEncoder(w).Encode(keys)
		LogAudit("list", "", "listed keys", v.masterKey)
		return
	default:
		switch r.Method {
		case http.MethodGet:
			if !CheckAccess(user, key, "read") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			val, err := v.Get(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"key": key, "value": val})
			LogAudit("get", key, "retrieved", v.masterKey)
		case http.MethodPost, http.MethodPut:
			if !CheckAccess(user, key, "write") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			body, _ := io.ReadAll(r.Body)
			if err := v.Set(key, string(body)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			LogAudit("set", key, "updated", v.masterKey)
		case http.MethodDelete:
			if !CheckAccess(user, key, "delete") {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if err := v.Delete(key); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			LogAudit("delete", key, "deleted", v.masterKey)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

// --- Tenant management ---

func initTenantEndpoints(mux *http.ServeMux) {
	// Add tenant
	mux.HandleFunc("/secretr/tenant/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		tenant, err := AddTenant(req.Name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"name":     tenant.Name,
			"adminKey": base64.StdEncoding.EncodeToString(tenant.AdminKey),
		})
	})

	// List tenants
	mux.HandleFunc("/secretr/tenant/list", func(w http.ResponseWriter, r *http.Request) {
		names := ListTenants()
		_ = json.NewEncoder(w).Encode(names)
	})

	// Set tenant admin key
	mux.HandleFunc("/secretr/tenant/setkey", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name string `json:"name"`
			Key  string `json:"key"` // base64
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Key == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		key, err := base64.StdEncoding.DecodeString(req.Key)
		if err != nil {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		if err := SetTenantAdminKey(req.Name, key); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Get tenant admin key
	mux.HandleFunc("/secretr/tenant/getkey", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		key, err := GetTenantAdminKey(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"key": base64.StdEncoding.EncodeToString(key)})
	})

	// Set tenant secret
	mux.HandleFunc("/secretr/tenant/secret/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name  string `json:"name"`
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Key == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := SetTenantSecret(req.Name, req.Key, req.Value); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Get tenant secret
	mux.HandleFunc("/secretr/tenant/secret/get", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		key := r.URL.Query().Get("key")
		if name == "" || key == "" {
			http.Error(w, "name and key required", http.StatusBadRequest)
			return
		}
		val, err := GetTenantSecret(name, key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": val})
	})
}

// --- Managed Keys API Endpoints ---

func initManagedKeysEndpoints(mux *http.ServeMux, v *Secretr) {
	// List managed keys metadata
	mux.Handle("/secretr/keys", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			keys := v.ListManagedKeys()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(keys)
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				ID    string `json:"id"`
				Type  string `json:"type"`
				Usage string `json:"usage"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			mk, err := v.CreateManagedKey(req.ID, KeyType(req.Type), req.Usage)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(mk.Metadata)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}))))

	// Rotate key
	mux.Handle("/secretr/keys/rotate", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		mk, err := v.RotateManagedKey(req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(mk.Metadata)
	}))))
	// Archive key
	mux.Handle("/secretr/keys/archive", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := v.ArchiveManagedKey(req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))))
	// Destroy key
	mux.Handle("/secretr/keys/destroy", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ ID string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := v.DestroyKeyAndAudit(req.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))))
}

// --- KV Secret Versions Endpoint ---

func initKVSecretVersionsEndpoint(mux *http.ServeMux, v *Secretr) {
	mux.Handle("/secretr/kv/versions", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "key parameter required", http.StatusBadRequest)
			return
		}
		versions, err := v.ListKVSecretVersions(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(versions)
	}))))
}

func StartSecureHTTPServer(v *Secretr, addr string) {
	mux := http.NewServeMux()
	initTransitEndpoints(mux, v)
	initTenantEndpoints(mux)
	initManagedKeysEndpoints(mux, v)
	initKVSecretVersionsEndpoint(mux, v)
	fileHandler := NewFileHandler(v)
	fileHandler.RegisterFileRoutes(mux)

	// Serve the frontend HTML (and static assets if needed)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeFile(w, r, "./web/index.html")
			return
		}
		// Optionally serve static files (css/js) from ./web/
		if strings.HasPrefix(r.URL.Path, "/web/") {
			http.StripPrefix("/web/", http.FileServer(http.Dir("./web"))).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})

	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		certFile := os.Getenv("SECRETR_HTTP_CERT")
		keyFile := os.Getenv("SECRETR_HTTP_KEY")
		if certFile != "" && keyFile != "" {
			log.Println("Starting HTTPS server on", addr)
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTPS server error: %v", err)
			}
		} else {
			log.Println("Starting HTTP server on", addr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("HTTP server error: %v", err)
			}
		}
	}()

	// Gracefully shutdown on termination signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}
	log.Println("Server gracefully stopped")
}
