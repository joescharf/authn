package auth0

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/url"
	"reflect"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-resty/resty/v2"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
)

func (a *Auth0) getJWKs() (*jwk.Set, error) {
	baseURL := fmt.Sprintf("%s.well-known/jwks.json", a.Config.Domain)
	jwks, err := jwk.Fetch(baseURL)
	return jwks, err
}
func (a *Auth0) ClearCachedTokens() {
	a.cachedManagementAPIToken = &jwt.Token{}
	a.cachedApplicationAPIToken = &jwt.Token{}
}

// GetManagementAPIToken Retrieves Auth0 Management API AccessToken
// audience: Tenant Domain + /api/v2/ (A0 Management API System Identifier)
func (a *Auth0) GetManagementAPIToken() (*jwt.Token, error) {

	// Check to see if we've cached the management token
	if a.cachedManagementAPIToken != nil && a.cachedManagementAPIToken.Valid {
		log.Debugln("Cached Management Token Returned")
		return a.cachedManagementAPIToken, nil
	} else {
		log.Debugln("New Management Token Returned")
		t, err := a.getToken(a.Config.Domain + "api/v2/")
		if err != nil {
			return t, err
		}
		a.cachedManagementAPIToken = t
		return t, err
	}
}

// GetApplicationAPIToken Retrieves Token for a Custom API
// audience: Custom API Identifier
func (a *Auth0) GetApplicationAPIToken() (*jwt.Token, error) {
	// Check to see if we've cached the application token
	if a.cachedApplicationAPIToken != nil && a.cachedApplicationAPIToken.Valid {
		log.Debugln("Cached Application Token Returned")
		return a.cachedApplicationAPIToken, nil
	} else {
		log.Debugln("New Application Token Returned")
		t, err := a.getToken(a.Config.APIIdentifier)
		if err != nil {
			return t, err
		}
		a.cachedApplicationAPIToken = t
		return t, err
	}

}

// getToken does the oAuth token retrieval from Auth0
// Because Auth0 needs audience in the oauth request, we can't use golang oauth2
// libraries as it doesn't support adding this field. So we have to manually make the request:
// oauth endpoint: https://[auth0_domain]/oauth/token
func (a *Auth0) getToken(audience string) (*jwt.Token, error) {
	jwtToken := new(jwt.Token)

	oaURL, _ := url.Parse(a.Config.Domain + "oauth/token")
	oaRequest := &OAuthRequest{
		ClientID:     a.Config.ClientID,
		ClientSecret: a.Config.ClientSecret,
		Audience:     audience,
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

	jwtToken, err = jwt.Parse(token.AccessToken, a.Validator(audience))
	return jwtToken, err
}

// Validator is the callback to supply signing key for verification
func (a *Auth0) Validator(aud string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		rsaPublicKey := new(rsa.PublicKey)
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Then check time based claims; exp, iat, nbf
			err := claims.Valid()
			if err != nil {
				return token, err
			}
			// Verify 'aud' claim
			// jwt-go prior to v4 doesn't handle multiple audience claims
			// So we have to handle them using the v4 validation code for now
			switch reflect.TypeOf(claims["aud"]).String() {
			case "string":
				if claims.VerifyAudience(aud, true) == false {
					err = errors.New("JWT: Error Validating aud Claims - Single aud case")
					return token, err
				}
			case "[]interface {}":
				// Type assert to []interface{}
				auds := claims["aud"].([]interface{})
				// Convert interface aud values to string slice:
				audsStr := make([]string, len(auds))
				for i, v := range auds {
					audsStr[i] = v.(string)
				}
				// Validate
				err = ValidateAudienceAgainst(audsStr, aud)

				if err != nil {
					err = errors.New("JWT: Error Validating aud Claims - Multiple aud case")
					return token, err
				}
			default:
				err = errors.New("JWT: Error Validating aud Claims - Unknown aud case")
				return token, err
			}
			// verify iss claim
			if claims.VerifyIssuer(a.Config.Domain, true) == false {
				err = errors.New("JWT: Invalid issuer")
				return token, err
			}

			// Validate the key
			// 1. Look up key
			kid := token.Header["kid"].(string)
			keys := a.JWKS.LookupKeyID(kid)
			if len(keys) == 0 {
				err = errors.New("JWKs: Failed to look up keys")
				return token, err
			}
			// 2. Build the public RSA key
			var key interface{}
			err = keys[0].Raw(&key)
			if err != nil {
				err = errors.New("JWKs: Failed to build public key")
				return token, err
			}
			rsaPublicKey = key.(*rsa.PublicKey)
		}

		return rsaPublicKey, nil
	}
}
