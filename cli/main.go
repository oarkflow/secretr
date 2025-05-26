package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"home/sujit/Projects/vault" // adjust if needed

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	v := vault.New()
	var rootCmd = &cobra.Command{
		Use:   "vault",
		Short: "Vault CLI with secure storage, import/export, and audit logging",
	}

	var setCmd = &cobra.Command{
		Use:   "set [key]",
		Args:  cobra.MinimumNArgs(1),
		Short: "Set a secret",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("Enter secret: ")
			pw, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err := v.Set(args[0], string(pw)); err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Println("Secret set.")
		},
	}
	var getCmd = &cobra.Command{
		Use:   "get [key]",
		Args:  cobra.MinimumNArgs(1),
		Short: "Get a secret",
		Run: func(cmd *cobra.Command, args []string) {
			val, err := v.Get(args[0])
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Println(val)
		},
	}
	var deleteCmd = &cobra.Command{
		Use:   "delete [key]",
		Args:  cobra.MinimumNArgs(1),
		Short: "Delete a secret",
		Run: func(cmd *cobra.Command, args []string) {
			if err := v.Delete(args[0]); err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Println("Secret deleted.")
		},
	}
	var exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export vault contents as JSON",
		Run: func(cmd *cobra.Command, args []string) {
			data, err := vault.ExportVault(v)
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Println(data)
		},
	}
	var importCmd = &cobra.Command{
		Use:   "import [file]",
		Short: "Import vault contents from JSON file",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			b, err := ioutil.ReadFile(args[0])
			if err != nil {
				fmt.Println("error:", err)
				return
			}
			if err := vault.ImportVault(v, string(b)); err != nil {
				fmt.Println("error:", err)
				return
			}
			fmt.Println("Vault imported.")
		},
	}
	var httpCmd = &cobra.Command{
		Use:   "http",
		Short: "Start the HTTP server",
		Run: func(cmd *cobra.Command, args []string) {
			vault.StartHTTPServer(v)
		},
	}

	rootCmd.AddCommand(setCmd, getCmd, deleteCmd, exportCmd, importCmd, httpCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
