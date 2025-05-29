package main

import (
	"flag"

	"github.com/oarkflow/secretr"
)

// main is the entry point for the secretr CLI application.
func main() {
	distributeKey := flag.Bool("distribute-key", false, "Distribute MasterKey using Shamir secret sharing")
	checkDevice := flag.Bool("check-device", true, "Check device fingerprint")
	flag.Parse()
	secretr.SetCheckDevice(*checkDevice)
	secretr.SetDistributeKey(*distributeKey)
	secretr.Execute(*distributeKey)
}
