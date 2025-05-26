package main

import (
	"fmt"

	"github.com/oarkflow/vault"
)

func main() {
	vault.LoadFromEnv()
	fmt.Println(vault.Get("HOME"))
	openAIKey, err := vault.Get("OPENAI_KEY")
	if err != nil {
		panic(err)
	}
	deepSeekKey, err := vault.Get("DEEPSEEK_KEY")
	if err != nil {
		panic(err)
	}
	fmt.Println("OPENAI_KEY  =", openAIKey)
	fmt.Println("DEEPSEEK_KEY  =", deepSeekKey)
}
