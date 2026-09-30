package coveclient_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lsariol/coveclient"
)

// A typical start-up: wait for Cove, get the token (the first run fetches and
// saves it), then read the secrets the program needs.
func Example() {
	c := coveclient.New("http://cove:2100", "", "myapp")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.WaitForReady(ctx); err != nil {
		log.Fatal(err)
	}

	if _, err := c.LoadOrBootstrap("/data/cove.token"); err != nil {
		log.Fatal(err)
	}

	secrets, err := c.GetSecrets("MYAPP_DATABASE_URL", "MYAPP_TMDB_API_KEY")
	if err != nil {
		log.Fatal(err) // names every missing key
	}
	fmt.Println(len(secrets))
}

func ExampleClient_GetSecret() {
	c := coveclient.New("http://cove:2100", "your-token", "myapp")

	value, err := c.GetSecret("MYAPP_TMDB_API_KEY")
	if errors.Is(err, coveclient.ErrNotFound) {
		log.Fatal("add MYAPP_TMDB_API_KEY in the Cove CLI: create MYAPP_TMDB_API_KEY")
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(value)
}

func ExampleAPIError() {
	c := coveclient.New("http://cove:2100", "your-token", "myapp")

	_, err := c.AddSecret("MYAPP_TMDB_API_KEY", "value")
	var apiErr *coveclient.APIError
	if errors.As(err, &apiErr) {
		fmt.Println(apiErr.StatusCode, apiErr.Type, apiErr.Message)
	}
}

func ExampleValidateKey() {
	fmt.Println(coveclient.ValidateKey("MYAPP_TMDB_API_KEY") == nil)
	fmt.Println(coveclient.ValidateKey("my app") == nil)
	// Output:
	// true
	// false
}
