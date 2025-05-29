package main

import (
	"fmt"

	"github.com/oarkflow/secretr/shamir"
)

func main() {
	secret := []byte("Top Secret Message")
	threshold, totalShares := 3, 5
	shares, err := shamir.Split(secret, threshold, totalShares)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated %d shares, threshold %d:\n", totalShares, threshold)
	for _, s := range shares {
		fmt.Printf("Share %d: %x\n", s[0], s[1:])
	}

	recovered, err := shamir.Combine(shares, threshold)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Recovered: %s\n", string(recovered))
}
