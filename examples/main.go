package main

import (
	"fmt"
	"os"

	"github.com/oarkflow/vault"
)

type Aws struct {
	Client string `json:"client,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// main demonstrates how to load environment variables from the vault and retrieve secrets.
func main() {
	os.Setenv("VAULT_MASTERKEY", "admintest")
	openAIKey, err := vault.Get("OPENAI_KEY")
	if err != nil {
		panic(err)
	}
	deepSeekKey, err := vault.Get("DEEPSEEK_KEY")
	if err != nil {
		panic(err)
	}
	fmt.Println("OPENAI_KEY  =", openAIKey)
	fmt.Println("DEEPSEEK_KEY =", deepSeekKey)

	var aws Aws
	err = vault.Unmarshal("aws", &aws)
	if err != nil {
		panic(err)
	}
	fmt.Println(aws)
}
