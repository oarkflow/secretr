package main

import (
	"fmt"
	"os"
	
	"github.com/oarkflow/secretr"
)

type Aws struct {
	Client string `json:"client,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// main demonstrates how to load environment variables from the secretr and retrieve secrets.
func main() {
	os.Setenv("SECRETR_MASTERKEY", "admintest")
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
	
	var aws Aws
	err = secretr.Unmarshal("aws", &aws)
	if err != nil {
		panic(err)
	}
	fmt.Println(aws)
}
