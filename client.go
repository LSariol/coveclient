package coveclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Client struct {
	BaseURL      string
	ClientSecret string
	Platform     string
}

func New(baseURL string, clientSecret string, platformName string) *Client {
	return &Client{
		BaseURL:      baseURL,
		ClientSecret: clientSecret,
		Platform:     strings.ToLower(platformName),
	}
}

func decodeEnvelope(resp *http.Response, out interface{}) error {
	var env apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if !env.Success {
		if env.Error != nil {
			return fmt.Errorf("coveClient: %s: %s", env.Error.Type, env.Error.Message)
		}
		return fmt.Errorf("coveClient: request failed (status %d)", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

func (c *Client) GetSecret(id string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v0/secrets/%s", c.BaseURL, id), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("X-Cove-Source", c.Platform)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("coveClient: Unexpected Status %d", resp.StatusCode)
	}

	var data struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	if err := decodeEnvelope(resp, &data); err != nil {
		return "", err
	}
	return data.Value, nil
}

func (c *Client) GetAllSecrets() ([]PublicSecretEntry, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v0/secrets", c.BaseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("coveClient: Unexpected Status %d", resp.StatusCode)
	}

	var data struct {
		Secrets []PublicSecretEntry `json:"secrets"`
	}
	if err := decodeEnvelope(resp, &data); err != nil {
		return nil, err
	}
	return data.Secrets, nil
}

func (c *Client) AddSecret(id string, value string) (string, error) {
	body, err := json.Marshal(secretPayload{Value: value})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v0/secrets/%s", c.BaseURL, id), bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cove-Source", c.Platform)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("coveClient: AddSecret: Unexpected Status %d", resp.StatusCode)
	}

	var data struct {
		Key     string `json:"key"`
		Action  string `json:"action"`
		Message string `json:"message"`
	}
	if err := decodeEnvelope(resp, &data); err != nil {
		return "", err
	}
	return data.Message, nil
}

func (c *Client) UpdateSecret(id string, value string) error {
	body, err := json.Marshal(secretPayload{Value: value})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PATCH", fmt.Sprintf("%s/v0/secrets/%s", c.BaseURL, id), bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cove-Source", c.Platform)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("coveClient: UpdateSecret: Unexpected Status %d", resp.StatusCode)
	}

	return decodeEnvelope(resp, nil)
}

func (c *Client) DeleteSecret(id string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v0/secrets/%s", c.BaseURL, id), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("X-Cove-Source", c.Platform)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("coveClient: DeleteSecret: Unexpected Status %d", resp.StatusCode)
	}

	return decodeEnvelope(resp, nil)
}

func (c *Client) Bootstrap() (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v0/bootstrap/lighthouse", c.BaseURL), nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("coveClient: Bootstrap: Unexpected Status %d", resp.StatusCode)
	}

	var data SecretValue
	if err := decodeEnvelope(resp, &data); err != nil {
		return "", err
	}
	return data.Secret, nil
}

func (c *Client) Health() (bool, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v0/health", c.BaseURL), nil)
	if err != nil {
		return false, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("coveClient: Health: Unexpected Status %d", resp.StatusCode)
	}

	var data struct {
		Healthy bool   `json:"healthy"`
		Time    string `json:"time"`
	}
	if err := decodeEnvelope(resp, &data); err != nil {
		return false, err
	}
	return data.Healthy, nil
}

func (c *Client) Auth() error {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v0/auth", c.BaseURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("coveClient: Auth: Unexpected Status %d", resp.StatusCode)
	}

	return decodeEnvelope(resp, nil)
}
