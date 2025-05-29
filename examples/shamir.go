package main

import (
	"fmt"

	"github.com/oarkflow/secretr/shamir"
	"github.com/oarkflow/secretr/storage"
	"github.com/oarkflow/secretr/storage/drivers"
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

	// Demonstration: Distribute shares into different storage backends using MultiStorage.
	ms := storage.New()
	store, err := drivers.NewFileStorage("./enc") // each share gets its own backend in this example
	if err != nil {
		panic(err)
	}
	// Assign a dedicated storage backend (MemoryStorage) for each share.
	for _, share := range shares {

		ms.AssignStorage(share[0], store)
	}
	// Store shares in their designated storage backends.
	if err := storage.StoreSharesMulti(shares, ms); err != nil {
		panic(err)
	}
	// Retrieve stored share indices.
	indices, err := ms.ListShares()
	if err != nil {
		panic(err)
	}
	// Reconstruct the secret using multi-party authorization from distributed storage.
	recovered, err := shamir.MultiPartyAuthorize(ms, indices, threshold)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Recovered from MultiStorage: %s\n", string(recovered))
}
