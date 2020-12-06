package auth0

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-resty/resty/v2"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
)

type (
	Config struct {
		APIIdentifier string `envconfig:"AUTH0_AUD_API_IDENTIFIER"`
		Domain        string `envconfig:"AUTH0_ISS_DOMAIN"`
		ClientID      string `envconfig:"AUTH0_CLIENT_ID"`
		ClientSecret  string `envconfig:"AUTH0_CLIENT_SECRET"`
	}

	OAuthRequest struct {
		ClientID     string `json:"client_id,omitempty"`
		ClientSecret string `json:"client_secret,omitempty"`
		Audience     string `json:"audience,omitempty"`
		GrantType    string `json:"grant_type,omitempty"`
	}
	OAuthResponse struct {
		AccessToken string `json:"access_token,omitempty"`
		TokenType   string `json:"token_type,omitempty"`
	}

	Auth0 struct {
		Config                    *Config
		JWKS                      *jwk.Set
		cachedManagementAPIToken  *jwt.Token
		cachedApplicationAPIToken *jwt.Token
	}

	SignupRequest struct {
		ClientID   string `json:"client_id"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		Connection string `json:"connection"`
		Username   string `json:"username,omitempty"`
		GivenName  string `json:"given_name,omitempty"`
		FamilyName string `json:"family_name,omitempty"`
		Name       string `json:"name,omitempty"`
		Nickname   string `json:"nickname,omitempty"`
		Picture    string `json:"picture,omitempty"`
	}

	SignupResponse struct {
		ID            string `json:"_id"`
		EmailVerified bool   `json:"email_verified"`
		Email         string `json:"email"`
		Username      string `json:"username"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Name          string `json:"name"`
		Nickname      string `json:"nickname"`
		Picture       string `json:"picture"`
	}

	AuthenticationAPIStatusResponse struct {
		Name        string `json:"name"`
		Code        string `json:"code"`
		Description string `json:"description"`
		StatusCode  int    `json:"statusCode"`
	}

	ManagementAPIStatusResponse struct {
		StatusCode int    `json:"statusCode"`
		Error      string `json:"error"`
		Message    string `json:"message"`
		ErrorCode  string `json:"errorCode"`
	}
)

func New(config *Config) *Auth0 {
	a0 := &Auth0{
		Config: config,
	}
	// Get the JWKs once and store them
	jwks, err := a0.getJWKs()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Errorln("Error getting JWKs")
		return a0
	}
	a0.JWKS = jwks
	return a0
}
func (a *Auth0) GetJWKS() *jwk.Set {
	return a.JWKS
}
func (a *Auth0) GetAudience() string {
	return a.Config.APIIdentifier
}
func (a *Auth0) GetDomain() string {
	return a.Config.Domain
}

// Signup uses Authentication API for signup
// requires an enabled connection from the M2M Application to the database
func (a *Auth0) Signup(email, password, connection string) (*SignupResponse, error) {
	baseURL, err := url.Parse(a.Config.Domain + "dbconnections/signup")

	signupRequest := &SignupRequest{
		ClientID:   a.Config.ClientID,
		Email:      email,
		Password:   password,
		Connection: connection,
	}
	signupResponse := new(SignupResponse)

	resp, err := resty.New().R().
		SetHeader("Accept", "application/json").
		SetBody(signupRequest).
		SetResult(&SignupResponse{}).
		Post(baseURL.String())

	// ERROR CHECKING!
	if resp.IsError() {
		errResp := new(AuthenticationAPIStatusResponse)
		json.Unmarshal(resp.Body(), errResp)
		err := fmt.Errorf("Error %d: %s", errResp.StatusCode, errResp.Description)
		return signupResponse, err
	}

	signupResponse = resp.Result().(*SignupResponse)

	return signupResponse, err
}

// Delete uses Management API for delete
// requires delete:users scope
func (a *Auth0) Delete(id string) error {
	token, err := a.GetManagementAPIToken()
	baseURL, err := url.Parse(a.Config.Domain + "api/v2/users/" + id)

	resp, err := resty.New().R().
		SetHeader("Accept", "application/json").
		SetAuthToken(token.Raw).
		Delete(baseURL.String())

	// ERROR CHECKING!
	if resp.IsError() {
		errResp := new(ManagementAPIStatusResponse)
		json.Unmarshal(resp.Body(), errResp)
		err := fmt.Errorf("Error %d: %s", errResp.StatusCode, errResp.Message)

		return err
	}

	return err
}
