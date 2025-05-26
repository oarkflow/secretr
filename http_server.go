package vault

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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

func StartHTTPServer(vault *Vault) {
	mux := http.NewServeMux()

	mux.HandleFunc("/vault/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/vault/")
		switch r.Method {
		case http.MethodGet:
			if key == "" || key == "keys" {
				keys := vault.List()
				json.NewEncoder(w).Encode(keys)
				return
			}
			val, err := vault.Get(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			fmt.Fprintln(w, val)
		case http.MethodPost, http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			_ = vault.Set(key, string(body))
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			_ = vault.Delete(key)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/vault/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}
		exp, err := ExportVault(vault)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, exp)
	})
	mux.HandleFunc("/vault/import", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if err := ImportVault(vault, string(body)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	handler := authMiddleware(rateLimitMiddleware(mux))
	go resetRateLimiter()
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	certFile := os.Getenv("VAULT_CERT")
	keyFile := os.Getenv("VAULT_KEY")
	if certFile != "" && keyFile != "" {

		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		server.TLSConfig = tlsCfg
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	} else {
		log.Fatal(server.ListenAndServe())
	}

}
