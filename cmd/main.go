package main

import (
	"flag"
	"log"

	"github.com/oarkflow/secretr"
)

// main is the entry point for the secretr CLI application.
func main() {
	distributeKey := flag.Bool("distribute-key", false, "Distribute MasterKey using Shamir secret sharing")
	checkDevice := flag.Bool("check-device", true, "Check device fingerprint")
	serverMode := flag.Bool("server", false, "Run in HTTP server mode")
	httpAddr := flag.String("http-addr", "", "HTTP server address for the API")
	// masterKey := flag.String("masterKey", "", "Master key for the Secretr instance (required)")
	userDB := flag.String("user-db", "users.csv", "User database CSV file for API authentication")
	flag.Parse()

	// Load user database if in server mode
	if *serverMode {
		// Only load user DB and start server, do NOT require MasterKey or open vault
		if err := secretr.LoadUserDB(*userDB); err != nil {
			log.Fatalf("Failed to load user database: %v", err)
		}
		v := secretr.New()
		v.SetDistributeKey(*distributeKey)
		// Do NOT call PromptMaster here
		secretr.StartSecureHTTPServer(v, *httpAddr)
		return
	}
	secretr.SetCheckDevice(*checkDevice)
	secretr.SetDistributeKey(*distributeKey)
	secretr.Execute(*distributeKey)
}
