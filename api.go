package secretr

import (
	"context"
	"crypto/tls"
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
)

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

	// KV secret versioning
	mux.Handle("/secretr/kv/versions", userAuthMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		versions, err := v.ListKVSecretVersions(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(versions)
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

// --- User token management ---

// Example: userTokens maps API tokens to usernames.
// In production, load from secure config or DB.
var userTokens = map[string]string{
	"admin-token-123": "admin",
	"user-token-abc":  "user",
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
		user, ok := userTokens[token]
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

// StartSecureHTTPServer initializes and runs an HTTP/HTTPS server with graceful shutdown.
func StartSecureHTTPServer(v *Secretr, addr string) {
	mux := http.NewServeMux()
	initTransitEndpoints(mux, v)

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
