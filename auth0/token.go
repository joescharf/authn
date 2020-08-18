package auth0

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

func (a *Auth0) GetToken() (*TokenResponse, error) {
	url := "https://scharfnado.us.auth0.com/oauth/token"

	tokenRequest := TokenRequest{
		ClientID:     a.Config.ClientID,
		ClientSecret: a.Config.ClientSecret,
		Audience:     a.Config.APIIdentifier,
		GrantType:    "client_credentials",
	}
	payload, _ := json.Marshal(tokenRequest)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))

	req.Header.Add("content-type", "application/json")

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	tokenResponse := new(TokenResponse)
	err := json.Unmarshal(body, tokenResponse)

	return tokenResponse, err
}
