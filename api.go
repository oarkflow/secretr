package vault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
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

func authMiddleware(next http.Handler) http.Handler {
	token := os.Getenv("VAULT_TOKEN")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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

func resetRateLimiter() {
	for {
		time.Sleep(time.Minute)
		limMu.Lock()
		limiter = make(map[string]int)
		limMu.Unlock()
	}
}

// vaultHTTPHandler dispatches HTTP methods for vault operations.
func vaultHTTPHandler(v *Vault, w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/vault/")
	switch r.Method {
	case http.MethodGet:
		if key == "" || key == "keys" {
			keys := v.List()
			json.NewEncoder(w).Encode(keys)
			LogAudit("list", "", "listed keys", v.masterKey)
			return
		}
		val, err := v.Get(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Write([]byte(val))
		LogAudit("get", key, "retrieved", v.masterKey)
	case http.MethodPost, http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if err := v.Set(key, string(body)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		LogAudit("set", key, "updated", v.masterKey)
	case http.MethodDelete:
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

// StartSecureHTTPServer runs the HTTP server using config from env,
// handles TLS if provided, and shuts down gracefully.
func StartSecureHTTPServer(v *Vault) {
	mux := http.NewServeMux()
	// Protect endpoints with auth and rate-limiting middleware.
	mux.Handle("/vault/", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultHTTPHandler(v, w, r)
	}))))

	mux.HandleFunc("/vault/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		exp, err := ExportVault(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(exp))
	})

	mux.HandleFunc("/vault/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := ImportVault(v, string(body)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		certFile := os.Getenv("VAULT_CERT")
		keyFile := os.Getenv("VAULT_KEY")
		if certFile != "" && keyFile != "" {
			log.Println("Starting HTTPS server on", addr)
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		} else {
			log.Println("Starting HTTP server on", addr)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}
	}()

	// Listen for termination signals and then shutdown gracefully.
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
