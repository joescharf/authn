package auth0

import (
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
)

func (a *Auth0) NewMiddleware() *jwtmiddleware.JWTMiddleware {
	jwtMiddleware := new(jwtmiddleware.JWTMiddleware)

	// Now create the jwtMiddleware with the options
	jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: a.Validator(a.Config.APIIdentifier),
		SigningMethod:       jwt.SigningMethodRS256,
	})

	return jwtMiddleware
}
