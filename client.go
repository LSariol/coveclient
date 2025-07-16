package coveclient

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
	var result SecretValue

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

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Secret, nil

}

func (c *Client) GetPublicKeyVault() ([]PublicSecretEntry, error) {

	var secrets []PublicSecretEntry

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/secrets", c.BaseURL), nil)
	if err != nil {
		return secrets, err
	}

	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return secrets, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return secrets, fmt.Errorf("coveClient: Unexpected Status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return secrets, err
	}

	return secrets, nil

}
