package main

import (
	"flag"
	
	"github.com/oarkflow/secretr"
)

// main is the entry point for the secretr CLI application.
func main() {
	guiFlag := flag.Bool("gui", true, "Run in GUI mode")
	flag.Parse()
	
	if *guiFlag {
		secretr.RunGUI()
		return
	}
	
	secretr.Execute()
}
