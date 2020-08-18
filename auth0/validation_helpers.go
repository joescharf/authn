package auth0

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// Adapted from upcoming v4 relase of go-jwt:
// https://github.com/dgrijalva/jwt-go/blob/release_4_0_0/validation_helper.go

// ValidateAudienceAgainst checks that the compare value is included in the aud list
// It is used by ValidateAudience, but exposed as a helper for other implementations
func ValidateAudienceAgainst(aud []string, compare string) error {
	if aud == nil {
		return nil
	}

	// Compare provided value with aud claim.
	// This code avoids the early return to make this check more or less constant time.
	// I'm not certain that's actually required in this context.
	var match = false
	for _, audStr := range aud {
		if subtle.ConstantTimeCompare([]byte(audStr), []byte(compare)) == 1 {
			match = true
		}
	}
	if !match {
		msg := fmt.Sprintf("'%v' wasn't found in aud claim", compare)
		err := errors.New(msg)
		return err
	}
	return nil

}
