package secretr

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

// resetRateLimiter periodically resets the rate limiter counts.
func resetRateLimiter() {
	for {
		time.Sleep(time.Minute)
		limMu.Lock()
		limiter = make(map[string]int)
		limMu.Unlock()
	}
}

// secretrHTTPHandler processes HTTP requests for secretr operations.
func secretrHTTPHandler(v *Secretr, w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/secretr/")
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

// StartSecureHTTPServer initializes and runs an HTTP/HTTPS server with graceful shutdown.
func StartSecureHTTPServer(v *Secretr) {
	mux := http.NewServeMux()
	// Protect endpoints with auth and rate-limiting middleware.
	mux.Handle("/secretr/", authMiddleware(rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secretrHTTPHandler(v, w, r)
	}))))

	mux.HandleFunc("/secretr/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		exp, err := ExportSecretr(v)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(exp))
	})

	mux.HandleFunc("/secretr/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := ImportSecretr(v, string(body)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
		w.Write([]byte(secret))
	})

	mux.HandleFunc("/secretr/ssh-key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
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
		} else if r.Method == http.MethodGet {
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "Name is required", http.StatusBadRequest)
				return
			}
			res := v.store.SSHKeys[name]
			json.NewEncoder(w).Encode(res)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/secretr/certificate", func(w http.ResponseWriter, r *http.Request) {
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
	})

	addr := os.Getenv("SECRETR_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		certFile := os.Getenv("SECRETR_CERT")
		keyFile := os.Getenv("SECRETR_KEY")
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
