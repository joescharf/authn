package auth0

import (
	"github.com/dgrijalva/jwt-go"
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
