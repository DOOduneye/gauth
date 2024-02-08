// dauth provides a simple, flexible authentication mechanism
// built around JWT (JSON Web Tokens) for Go applications. It supports
// generating access and refresh tokens with customizable lifetimes and
// secrets, validating tokens, and extracting claims.
//
// Example usage:
// // put example code here
package dauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// Auth configures and manages token generation and validation for
// access and refresh tokens. It encapsulates configurations for both
// token types, allowing for separate secrets and durations.
type Auth struct {
	accessConfig  TokenConfig // Configuration for access tokens
	refreshConfig TokenConfig // Configuration for refresh tokens
}

// TokenConfig defines the secret key and duration for a token type.
// The secret key is used to sign the token, and the duration defines
// how long the token is valid.
type TokenConfig struct {
	secret   string        // Secret key used for signing tokens
	duration time.Duration // Token validity duration
}

// Token wraps the jwt.Token to provide additional functionality
// or customization specific to the dauth package if needed.
type Token struct {
	*jwt.Token
}

// TokenType distinguishes between access and refresh tokens,
// allowing for different handling and configuration.
type TokenType string

const (
	tokenTypeAccess  TokenType = "access"  // Represents an access token
	tokenTypeRefresh TokenType = "refresh" // Represents a refresh token
)

// NewAuth initializes a new Auth instance with optional configuration
// options, such as token secrets and durations for access and refresh tokens.
// This allows for flexible and dynamic configuration of the authentication mechanism.
func NewAuth(options ...func(*Auth)) *Auth {
	var auth Auth
	for _, option := range options {
		option(&auth)
	}
	return &auth
}

// WithAccessTokenConfig returns a configuration option for setting the
// access token's secret and duration. This option can be passed to NewAuth
// to configure the access token parameters.
func WithAccessTokenConfig(secret string, duration time.Duration) func(*Auth) {
	return func(a *Auth) {
		a.accessConfig = TokenConfig{secret: secret, duration: duration}
	}
}

// WithRefreshTokenConfig returns a configuration option for setting the
// refresh token's secret and duration. This option can be passed to NewAuth
// to configure the refresh token parameters.
func WithRefreshTokenConfig(secret string, duration time.Duration) func(*Auth) {
	return func(a *Auth) {
		a.refreshConfig = TokenConfig{secret: secret, duration: duration}
	}
}

// GenerateToken creates a token of the specified type (access or refresh)
// with the given claims. It returns the signed token string or an error if
// the token could not be generated.
func (a *Auth) GenerateToken(claims jwt.Claims, tokenType TokenType) (*string, error) {
	var tokenConfig TokenConfig
	switch tokenType {
	case tokenTypeAccess:
		tokenConfig = a.accessConfig
	case tokenTypeRefresh:
		tokenConfig = a.refreshConfig
	default:
		return nil, fmt.Errorf("unknown token type")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(tokenConfig.secret))
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

// GenerateTokenPair generates a pair of tokens (access and refresh) for the
// provided claims. This is useful for sessions where both an access token and
// a refresh token are required.
func (a *Auth) GenerateTokenPair(accessClaims, refreshClaims jwt.Claims) (accessToken *string, refreshToken *string, err error) {
	accessToken, err = a.GenerateToken(accessClaims, tokenTypeAccess)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err = a.GenerateToken(refreshClaims, tokenTypeRefresh)
	if err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

// ParseToken validates the token string and returns the parsed token if valid.
// The token's signature is verified using the access token's secret.
func (a *Auth) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.accessConfig.secret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// ExtractClaims extracts the claims from a valid token string. This is useful
// for retrieving user information or other data encoded in the token.
func (a *Auth) ExtractClaims(tokenString string) (jwt.Claims, error) {
	token, err := a.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}
	return token.Claims, nil
}

// IsValid checks the validity of the token string. It returns true if the
// token is valid, false otherwise.
func (a *Auth) IsValid(tokenString string) bool {
	claim, err := a.ParseToken(tokenString)
	if err != nil {
		return false
	}

	return claim.Valid
}

// RefreshToken generates a new access token using the claims from the provided
// token string. This is useful for extending user sessions without requiring
// re-authentication.
func (a *Auth) RefreshToken(tokenString string) (*string, error) {
	claims, err := a.ExtractClaims(tokenString)
	if err != nil {
		return nil, err
	}

	// Generate a new access token
	accessToken, err := a.GenerateToken(claims, tokenTypeAccess)
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}
