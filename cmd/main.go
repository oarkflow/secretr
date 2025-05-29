package main

import (
	"flag"

	"github.com/oarkflow/secretr"
)

// main is the entry point for the secretr CLI application.
func main() {
	distributeKey := flag.Bool("distribute-key", false, "Distribute MasterKey using Shamir secret sharing")
	flag.Parse()
	secretr.SetDistributeKey(*distributeKey)
	secretr.Execute(*distributeKey)
}
