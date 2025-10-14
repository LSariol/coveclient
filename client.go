package coveclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

func (c *Client) GetAllSecrets() ([]PublicSecretEntry, error) {

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

func (c *Client) AddSecret(ID string, password string) (string, error) {

	load := payload{
		SecretID:    ID,
		SecretValue: password,
	}

	jsonData, err := json.Marshal(load)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/secrets/%s", c.BaseURL, ID)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	//Handle Response
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("AddSecret: status %d - %s", resp.StatusCode, string(bodyBytes))
	}

	//Read Response
	var res response
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}

	return res.Message, nil

}

func (c *Client) UpdateSecret(ID string, password string) error {
	load := payload{
		SecretID:    ID,
		SecretValue: password,
	}

	jsonData, err := json.Marshal(load)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/secrets/%s", c.BaseURL, ID)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//Handle Response
	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("UpdateSecret: status %d - %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (c *Client) DeleteSecret(ID string) error {
	load := payload{
		SecretID:    ID,
		SecretValue: "",
	}

	jsonData, err := json.Marshal(load)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/secrets/%s", c.BaseURL, ID)
	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//Handle Response
	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("DeleteSecret: status %d - %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (c *Client) Bootstrap() (string, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/bootstrap/lighthouse", c.BaseURL), nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("boostrap: bad status %d", resp.StatusCode)
	}

	var result SecretValue
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Secret, nil

}
