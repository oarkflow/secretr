package main

import (
	"flag"

	"github.com/oarkflow/vault"
)

// main is the entry point for the vault CLI application.
func main() {
	guiFlag := flag.Bool("gui", true, "Run in GUI mode")
	flag.Parse()

	if *guiFlag {
		vault.RunGUI()
		return
	}

	vault.Execute()
}
