package main

import (
	"fmt"
	"os"

	"github.com/oarkflow/secretr/gui"
)

// main is the entry point for the secretr GUI application.
func main() {
	// Add panic recovery to prevent crashes
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal error in Secretr GUI: %v\n", r)
			os.Exit(1)
		}
	}()

	gui.RunGUI()
}
