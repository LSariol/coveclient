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
	c := coveclient.New("http://10.0.0.159:2100", "", "myapp")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.WaitForReady(ctx); err != nil {
		log.Fatal(err)
	}

	if _, err := c.LoadOrBootstrap("/data/cove.token"); err != nil {
		log.Fatal(err)
	}

	secrets, err := c.GetSecrets("myapp.db-url", "myapp.api-key")
	if err != nil {
		log.Fatal(err) // names every missing key
	}
	fmt.Println(len(secrets))
}

func ExampleClient_GetSecret() {
	c := coveclient.New("http://10.0.0.159:2100", "your-token", "myapp")

	value, err := c.GetSecret("myapp.api-key")
	if errors.Is(err, coveclient.ErrNotFound) {
		log.Fatal("add myapp.api-key in the Cove CLI: create myapp.api-key")
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(value)
}

func ExampleAPIError() {
	c := coveclient.New("http://10.0.0.159:2100", "your-token", "myapp")

	_, err := c.AddSecret("myapp.api-key", "value")
	var apiErr *coveclient.APIError
	if errors.As(err, &apiErr) {
		fmt.Println(apiErr.StatusCode, apiErr.Type, apiErr.Message)
	}
}

func ExampleValidateKey() {
	fmt.Println(coveclient.ValidateKey("myapp.api-key") == nil)
	fmt.Println(coveclient.ValidateKey("my app") == nil)
	// Output:
	// true
	// false
}
