package main

import (
	"fmt"
	"os"
	"time"

	"github.com/oarkflow/secretr"
)

type Aws struct {
	Client string `json:"client,omitempty"`
	Secret string `json:"secret,omitempty"`
}

func main() {
	os.Setenv("SECRETR_MASTERKEY", "test1234")

	// Existing examples retrieving previously stored secrets.
	openAIKey, err := secretr.Get("OPENAI_KEY")
	if err != nil {
		panic(err)
	}
	deepSeekKey, err := secretr.Get("DEEPSEEK_KEY")
	if err != nil {
		panic(err)
	}
	fmt.Println("OPENAI_KEY  =", openAIKey)
	fmt.Println("DEEPSEEK_KEY =", deepSeekKey)
	dynSecret, err := secretr.GenerateDynamicSecret("temp_db_user", 5*time.Minute)
	if err != nil {
		panic(err)
	}
	fmt.Println("Dynamic secret for temp_db_user:", dynSecret)

	// NEW: Example of transit encryption and decryption.
	plaintext := "my sensitive data"
	encrypted, err := secretr.TransitEncrypt(plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Println("Encrypted text:", encrypted)
	decrypted, err := secretr.TransitDecrypt(encrypted)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted text:", decrypted)
}
