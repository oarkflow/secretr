package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/oarkflow/secretr"
)

// main is the entry point for the secretr CLI application.
func main() {
	distributeKey := flag.Bool("distribute-key", false, "Distribute MasterKey using Shamir secret sharing")
	checkDevice := flag.Bool("check-device", true, "Check device fingerprint")
	serverMode := flag.Bool("server", false, "Run in HTTP server mode")
	httpAddr := flag.String("http-addr", "", "HTTP server address for the API")
	masterKey := flag.String("masterKey", "", "Master key for the Secretr instance (required)")
	flag.Parse()
	if *serverMode {
		if *masterKey == "" {
			log.Fatal("Master key is required when starting the HTTP server")
		}
		os.Setenv("SECRETR_MASTERKEY", *masterKey)
		os.Setenv("SECRETR_KEY", secretr.GenerateRandomString())
		v := secretr.New()
		v.SetDistributeKey(*distributeKey)
		err := v.PromptMaster()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		secretr.StartSecureHTTPServer(v, *httpAddr)
		return
	}
	secretr.SetCheckDevice(*checkDevice)
	secretr.SetDistributeKey(*distributeKey)
	secretr.Execute(*distributeKey)
}
