package main

import (
	"fmt"
	"os"

	"github.com/fatz/ghpubkey-go/ghpubkey"
)

func main() {
	g := ghpubkey.NewGHPubKey()

	user := "fatz"

	authorizedKeys, err := g.RequestKeysForUser(user)
	if err != nil {
		fmt.Printf("Can't retreive keys for user %s - %v", user, err)
		os.Exit(1)
	}

	fmt.Print(authorizedKeys)
	os.Exit(0)
}
