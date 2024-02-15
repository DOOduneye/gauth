package gauth

import (
	"errors"

	m "github.com/garrettladley/mattress"
	"github.com/golang-jwt/jwt"
)

type Auth struct {
	AccessConfig  AccessTokenConfig
	RefreshConfig RefreshTokenConfig
}

// AccessTokenConfig is a builder for configuring access token options.
type AccessTokenConfig struct {
	secretKey      *m.Secret[[]byte]
	standardClaims jwt.StandardClaims
	customClaims   map[string]interface{}
}

// RefreshTokenConfig is a builder for configuring refresh token options.
type RefreshTokenConfig struct {
	secretKey      *m.Secret[[]byte]
	standardClaims jwt.StandardClaims
	customClaims   map[string]interface{}
}

// NewAccessTokenConfigBuilder creates a new instance of AccessTokenConfig.
func NewAccessTokenConfigBuilder(secretKey []byte) (*AccessTokenConfig, error) {
	if secretKey == nil {
		return nil, errors.New("secret key is required")
	}

	secret, err := m.NewSecret(secretKey)
	if err != nil {
		return nil, err
	}

	return &AccessTokenConfig{
		secretKey: secret,
	}, nil
}

// NewRefreshTokenConfigBuilder creates a new instance of RefreshTokenConfig.
func NewRefreshTokenConfigBuilder(secretKey []byte) (*RefreshTokenConfig, error) {
	if secretKey == nil {
		return nil, errors.New("secret key is required")
	}

	secret, err := m.NewSecret(secretKey)
	if err != nil {
		return nil, err
	}

	return &RefreshTokenConfig{
		secretKey: secret,
	}, nil
}

// WithStandardClaims sets the standard claims for the access token.
func (b *AccessTokenConfig) WithStandardClaims(claims jwt.StandardClaims) *AccessTokenConfig {
	b.standardClaims = claims
	return b
}

// WithStandardClaims sets the standard claims for the refresh token.
func (b *RefreshTokenConfig) WithStandardClaims(claims jwt.StandardClaims) *RefreshTokenConfig {
	b.standardClaims = claims
	return b
}

// WithCustomClaims sets the custom claims for the access token.
func (b *AccessTokenConfig) WithCustomClaims(claims map[string]interface{}) *AccessTokenConfig {
	b.customClaims = claims
	return b
}

// WithCustomClaims sets the custom claims for the refresh token.
func (b *RefreshTokenConfig) WithCustomClaims(claims map[string]interface{}) *RefreshTokenConfig {
	b.customClaims = claims
	return b
}

// Build builds the access token configuration.
func (b *AccessTokenConfig) Build() AccessTokenConfig {
	return AccessTokenConfig{
		secretKey:      b.secretKey,
		standardClaims: b.standardClaims,
		customClaims:   b.customClaims,
	}
}

// Build builds the refresh token configuration.
func (b *RefreshTokenConfig) Build() RefreshTokenConfig {
	return RefreshTokenConfig{
		secretKey:      b.secretKey,
		standardClaims: b.standardClaims,
		customClaims:   b.customClaims,
	}
}

// WithAccessTokenConfig returns a function that sets the access token configuration using the builder pattern.
func WithAccessTokenConfig(secretKey []byte, configurators ...func(*AccessTokenConfig)) func(*Auth) {
	builder, err := NewAccessTokenConfigBuilder(secretKey)
	if err != nil {
		panic(err)
	}

	for _, configurator := range configurators {
		configurator(builder)
	}

	return func(a *Auth) {
		a.AccessConfig = builder.Build()
	}
}

// WithRefreshTokenConfig returns a function that sets the refresh token configuration using the builder pattern.
func WithRefreshTokenConfig(secretKey []byte, configurators ...func(*RefreshTokenConfig)) func(*Auth) {
	builder, err := NewRefreshTokenConfigBuilder(secretKey)
	if err != nil {
		panic(err)
	}

	for _, configurator := range configurators {
		configurator(builder)
	}

	return func(a *Auth) {
		a.RefreshConfig = builder.Build()
	}
}

// NewAuth creates a new Auth instance with the provided access and refresh token configurations.
func NewAuth(accessConfig AccessTokenConfig, refreshConfig RefreshTokenConfig) *Auth {
	return &Auth{
		AccessConfig:  accessConfig,
		RefreshConfig: refreshConfig,
	}
}

// GenerateAccessToken generates a new access token using the configured options.
func (a *Auth) GenerateAccessToken(signingMethod jwt.SigningMethod) (string, error) {
	token := jwt.NewWithClaims(signingMethod, a.AccessConfig.standardClaims)
	return token.SignedString(a.AccessConfig.secretKey.Expose())
}

// GenerateRefreshToken generates a new refresh token using the configured options.
func (a *Auth) GenerateRefreshToken(signingMethod jwt.SigningMethod) (string, error) {
	token := jwt.NewWithClaims(signingMethod, a.RefreshConfig.standardClaims)
	return token.SignedString(a.RefreshConfig.secretKey.Expose())
}

// verifyToken verifies a token using the provided signing method and secret key.
func (a *Auth) verifyToken(tokenString string, signingMethod jwt.SigningMethod, secretKey *m.Secret[[]byte]) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != signingMethod {
			return nil, errors.New("invalid signing method")
		}

		return secretKey.Expose(), nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}

// VerifyAccessToken verifies an access token using the configured options.
func (a *Auth) VerifyAccessToken(tokenString string, signingMethod jwt.SigningMethod) (*jwt.Token, error) {
	return a.verifyToken(tokenString, signingMethod, a.AccessConfig.secretKey)
}

// VerifyRefreshToken verifies a refresh token using the configured options.
func (a *Auth) VerifyRefreshToken(tokenString string, signingMethod jwt.SigningMethod) (*jwt.Token, error) {
	return a.verifyToken(tokenString, signingMethod, a.RefreshConfig.secretKey)
}

// RefreshAccessToken refreshes the access token using the configured options.
func (a *Auth) RefreshAccessToken(tokenString string, signingMethod jwt.SigningMethod) (string, error) {
	token, err := a.VerifyAccessToken(tokenString, signingMethod)
	if err != nil {
		return "", err
	}

	_, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return a.GenerateAccessToken(signingMethod)
}

// RefreshRefreshToken refreshes the refresh token using the configured options.
func (a *Auth) RefreshRefreshToken(tokenString string, signingMethod jwt.SigningMethod) (string, error) {
	token, err := a.VerifyRefreshToken(tokenString, signingMethod)
	if err != nil {
		return "", err
	}

	_, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	return a.GenerateRefreshToken(signingMethod)
}
