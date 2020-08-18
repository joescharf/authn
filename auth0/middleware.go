package auth0

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
)

func (a *Auth0) NewMiddleware() *jwtmiddleware.JWTMiddleware {
	var err error
	jwtMiddleware := new(jwtmiddleware.JWTMiddleware)

	// Now create the jwtMiddleware with the options
	jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			rsaPublicKey := new(rsa.PublicKey)
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				// Then check time based claims; exp, iat, nbf
				err = claims.Valid()
				if err != nil {
					log.WithFields(log.Fields{"err": err}).Errorln("JWT: Invalid Claims")
					return token, err
				}
				// Verify 'aud' claim
				// jwt-go prior to v4 doesn't handle multiple audience claims
				// So we have to handle them using the v4 validation code for now
				switch reflect.TypeOf(claims["aud"]).String() {
				case "string":
					if claims.VerifyAudience(a.Config.APIIdentifier, true) == false {
						err = errors.New("JWT: Invalid audience")
						log.WithFields(log.Fields{"err": err}).Errorln("Error Validating JWT aud Claims")
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
					err = ValidateAudienceAgainst(audsStr, a.Config.APIIdentifier)

					if err != nil {
						log.WithFields(log.Fields{"err": err}).Errorln("Error Validating JWT aud Claims")
						return token, err
					}
				default:
					log.WithFields(log.Fields{"err": err}).Errorln("Error Validating JWT aud Claims")
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
				err := keys[0].Raw(&key)
				if err != nil {
					log.WithFields(log.Fields{"err": err}).Errorln("JWK Failed to build public key")
					return token, err
				}
				rsaPublicKey = key.(*rsa.PublicKey)
			}

			return rsaPublicKey, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	return jwtMiddleware
}

func (a *Auth0) getJWKs() (*jwk.Set, error) {
	baseURL := fmt.Sprintf("%s.well-known/jwks.json", a.Config.Domain)
	jwks, err := jwk.Fetch(baseURL)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Errorln("Error retrieving well-known JWKS")
	}
	return jwks, err
}
