package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// Auth represents the authentication service.
type Auth struct {
	accessConfig  TokenConfig
	refreshConfig TokenConfig
}

// TokenConfig holds configuration details for tokens.
type TokenConfig struct {
	Secret   string
	Duration time.Duration
}

// Token represents a JWT token.
type Token struct {
	*jwt.Token
}

// TokenType represents an enum for token types.
type TokenType string

var (
	tokenTypeAccess  TokenType = "access"
	tokenTypeRefresh TokenType = "refresh"
)

// NewAuth creates a new instance of the Auth service with provided options.
func NewAuth(options ...func(*Auth)) *Auth {
	auth := &Auth{}
	for _, option := range options {
		option(auth)
	}
	return auth
}

// WithAccessTokenConfig configures the access token settings.
func WithAccessTokenConfig(secret string, duration time.Duration) func(*Auth) {
	return func(a *Auth) {
		a.accessConfig = TokenConfig{Secret: secret, Duration: duration}
	}
}

// WithRefreshTokenConfig configures the refresh token settings.
func WithRefreshTokenConfig(secret string, duration time.Duration) func(*Auth) {
	return func(a *Auth) {
		a.refreshConfig = TokenConfig{Secret: secret, Duration: duration}
	}
}

// GenerateToken generates a new token with the given claims and type.
func (a *Auth) GenerateToken(claims jwt.Claims,	tokenType TokenType) (*string, error) {
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
	tokenString, err := token.SignedString([]byte(tokenConfig.Secret))
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

// GenerateTokenPair generates a new access and refresh token with the given claims.
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


// ParseToken parses the given token 
func (a *Auth) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.accessConfig.Secret), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

// ExtractClaims extracts the claims from the given token.
func (a *Auth) ExtractClaims(tokenString string) (jwt.Claims, error) {
	token, err := a.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}
	return token.Claims, nil
}

// IsValid checks if the given token is valid.
func (a *Auth) IsValid(tokenString string) bool {
	claim, err := a.ParseToken(tokenString)
	if err != nil {
		return false
	}

	return claim.Valid	
}

// RefreshToken refreshes the given access token and returns a new token.
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
