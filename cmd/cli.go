package main

import (
	"fmt"
	"os"

	"github.com/oarkflow/vault"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "vault",
		Short: "Vault CLI",
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "set [key] [value]",
		Short: "Set a vault key",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if err := vault.GetDefaultVault().Set(args[0], args[1]); err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			fmt.Println("Key set:", args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "get [key]",
		Short: "Get a vault key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			val, err := vault.GetDefaultVault().Get(args[0])
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			fmt.Println(val)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "delete [key]",
		Short: "Delete a vault key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := vault.GetDefaultVault().Delete(args[0]); err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			fmt.Println("Key deleted:", args[0])
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "export",
		Short: "Export vault as encrypted JSON",
		Run: func(cmd *cobra.Command, args []string) {
			exp, err := vault.ExportVault(vault.GetDefaultVault())
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			fmt.Println(exp)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "import [file]",
		Short: "Import vault from encrypted JSON file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			data, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			if err := vault.ImportVault(vault.GetDefaultVault(), string(data)); err != nil {
				fmt.Println("Error:", err)
				os.Exit(1)
			}
			fmt.Println("Vault imported successfully")
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
