package CoveClient

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	BaseURL      string
	ClientSecret string
}

func New(baseURL, ClientSecret string) *Client {
	return &Client{
		BaseURL:      baseURL,
		ClientSecret: ClientSecret,
	}
}

func (c *Client) GetSecret(id string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/secrets/%s", c.BaseURL, id), nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("coveClient: Unexpected Status %d", resp.StatusCode)
	}

	var result struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Value, nil

}
