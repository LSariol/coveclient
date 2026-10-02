// Command basic reads secrets from Cove and prints their lengths (never the
// values).
//
//	COVE_URL=http://cove:2100 COVE_TOKEN_FILE=./cove.token \
//	    go run ./examples/basic MYAPP_DATABASE_URL MYAPP_TMDB_API_KEY
//
// The first run fetches the token from Cove's bootstrap endpoint (open it
// first with `bootstrap open` in the Cove CLI) and saves it to COVE_TOKEN_FILE.
// Later runs read the file. Set COVE_TOKEN instead to use a token you have.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lsariol/coveclient"
)

func main() {
	log.SetFlags(0)

	baseURL := os.Getenv("COVE_URL")
	if baseURL == "" {
		log.Fatal("set COVE_URL, e.g. http://cove:2100")
	}
	keys := os.Args[1:]
	if len(keys) == 0 {
		log.Fatal("usage: basic KEY [KEY...]")
	}

	c := coveclient.New(baseURL, os.Getenv("COVE_TOKEN"))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.WaitForReady(ctx); err != nil {
		log.Fatal(err)
	}

	if c.Token == "" {
		tokenFile := os.Getenv("COVE_TOKEN_FILE")
		if tokenFile == "" {
			tokenFile = "cove.token"
		}
		if _, err := c.LoadOrBootstrap(tokenFile); err != nil {
			log.Fatal(err)
		}
	}

	secrets, err := c.GetSecretsContext(ctx, keys...)
	if err != nil {
		log.Fatal(err)
	}
	for _, key := range keys {
		fmt.Printf("%s: %d characters\n", key, len(secrets[key]))
	}
}
