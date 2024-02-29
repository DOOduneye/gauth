package hydrate

import "errors"

// These errors are returned when an error occurs during token generation, verification, or refreshing.
var (
	ErrInvalidSecretKey     = errors.New("invalid secret key")
	ErrTokenInvalid         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token expired")
	ErrClaimsInvalid        = errors.New("invalid claims in token")
	ErrSigningMethodNil     = errors.New("signing method cannot be nil")
	ErrStandardClaimMissing = errors.New("standard claim 'exp' is required")
	ErrCustomClaimsMissing  = errors.New("custom claims are required")
	ErrTokenNotGenerated    = errors.New("token not generated")
	ErrSigningToken         = errors.New("error signing token")
	ErrStoringToken         = errors.New("error storing token")
	ErrInvalidTokenConfig   = errors.New("invalid token configuration")
	ErrTokenConfigNil       = errors.New("token configuration cannot be nil")
)