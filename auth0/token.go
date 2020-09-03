package auth0

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-resty/resty/v2"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
)

func (a *Auth0) getJWKs() (*jwk.Set, error) {
	baseURL := fmt.Sprintf("%s.well-known/jwks.json", a.Config.Domain)
	jwks, err := jwk.Fetch(baseURL)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Errorln("Error retrieving well-known JWKS")
	}
	return jwks, err
}

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

// GetToken2 Retrieves Auth0 Management API AccessToken
// Because Auth0 needs audience in the oauth request, we can't use golang oauth2
// libraries as it doesn't support adding this field. So we have to manually make the request:
// oauth endpoint: https://auth0_domain/oauth/token
func (a *Auth0) GetToken2() (*jwt.Token, error) {
	jwtToken := new(jwt.Token)

	oaURL, _ := url.Parse(a.Config.Domain + "oauth/token")
	oaRequest := &OAuthRequest{
		ClientID:     a.Config.ClientID,
		ClientSecret: a.Config.ClientSecret,
		Audience:     a.Config.Domain + "api/v2/",
		GrantType:    "client_credentials",
	}

	c := resty.New()
	oaResp, err := c.R().
		SetResult(&OAuthResponse{}).
		SetBody(oaRequest).
		Post(oaURL.String())
	token := oaResp.Result().(*OAuthResponse)
	if err != nil {
		return jwtToken, err
	}
	jwtToken, err = jwt.Parse(token.AccessToken, a.Validator())
	if err != nil {
		return jwtToken, err
	}
	spew.Dump(jwtToken)
	return jwtToken, err

}

// Validator is the callback to supply signing key for verification
func (a *Auth0) Validator() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		rsaPublicKey := new(rsa.PublicKey)
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Then check time based claims; exp, iat, nbf
			err := claims.Valid()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("JWT: Invalid Claims")
				return token, err
			}
			// Verify 'aud' claim
			if claims.VerifyAudience(a.Config.APIIdentifier, true) == false {
				err = errors.New("JWT: Invalid audience")
				log.WithFields(log.Fields{"err": err}).Errorln("JWT aud validation")
				return token, err
			}
			// verify iss claim
			if claims.VerifyIssuer(a.Config.Domain, true) == false {
				err = errors.New("JWT: Invalid issuer")
				log.WithFields(log.Fields{"err": err}).Errorln("JWT aud validation")
				return token, err
			}

			// Validate the key
			// 1. Look up key
			kid := token.Header["kid"].(string)
			keys := a.JWKS.LookupKeyID(kid)
			if len(keys) == 0 {
				err = errors.New("JWKs: Failed to look up keys")
				log.WithFields(log.Fields{"err": err}).Errorln("JWK RSA validation")
				return token, err
			}
			// 2. Build the public RSA key
			var key interface{}
			err = keys[0].Raw(&key)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Errorln("JWK Failed to build public key")
				return token, err
			}
			rsaPublicKey = key.(*rsa.PublicKey)
		}

		return rsaPublicKey, nil
	}
}
