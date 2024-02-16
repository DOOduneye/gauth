// hydrate provides a simple, flexible authentication mechanism
// built around JWT (JSON Web Tokens) for Go applications. It supports
// the generation, verification and refreshing of access and refresh tokens.
//
// Example Usage:
//
// import (
//
//	"fmt"
//	"time"
//
//	"github.com/golang-jwt/jwt"
//	"github.com/garrettladley/hydrate"
//
//	m "github.com/garrettladley/mattress"
//
// )
//
//	func main() {
//	    access, err := hydrate.NewAccessTokenConfigBuilder([]byte("secret"))
//	    if err != nil {
//	        fmt.Println(err)
//	        return
//	    }
//
//	    access.WithStandardClaims(jwt.StandardClaims{
//	        ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
//	        Issuer:    "test",
//	        Audience:  "test",
//	    })
//
//	    access.WithCustomClaims(map[string]interface{}{
//	        "role": "admin",
//	    })
//
//	    refresh, err := hydrate.NewRefreshTokenConfigBuilder([]byte("secret"))
//	    if err != nil {
//	        fmt.Println(err)
//	        return
//	    }
//
//	    refresh.WithStandardClaims(jwt.StandardClaims{
//	        ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
//	    })
//
//	    auth := hydrate.NewAuth(
//	        hydrate.WithAccessTokenConfig(access),
//	        hydrate.WithRefreshTokenConfig(refresh),
//	    )
//
//	    accessToken, refreshToken, err := auth.GenerateTokenPair(jwt.SigningMethodHS256)
//	    if err != nil {
//	        fmt.Println(err)
//	        return
//	    }
//
//	    fmt.Println("Access Token:", *accessToken)
//	    fmt.Println("Refresh Token:", *refreshToken)
//	}
package hydrate

import (
	"errors"

	m "github.com/garrettladley/mattress"
	"github.com/golang-jwt/jwt"
)

// Auth configures and manages token generation and validation for
// access and refresh tokens. It encapsulates configurations for both
// token types, allowing for separate secrets and claims.
// Also supports additional token configurations for other token types.
type Auth struct {
	AccessConfig  TokenConfig // Configuration for access tokens
	RefreshConfig TokenConfig // Configuration for refresh tokens
}

// TokenConfig defines the configuration for tokens.
// These include the secret key, standard claims, and custom claims.
type TokenConfig struct {
	secretKey      *m.Secret[[]byte]      // Secret key used to sign the token
	standardClaims jwt.StandardClaims     // Standard claims for the token
	customClaims   map[string]interface{} // Custom claims for the token
}

// NewTokenConfigBuilder instantiates a new instance of TokenConfig with the provided secret key.
// If the secret key is nil, an error is returned.
func NewTokenConfigBuilder(secretKey []byte) (*TokenConfig, error) {
	if secretKey == nil {
		return nil, errors.New("secret key is required")
	}

	secret, err := m.NewSecret(secretKey)
	if err != nil {
		return nil, err
	}

	return &TokenConfig{
		secretKey: secret,
	}, nil
}

// WithStandardClaims sets the standard claims for the token.
// Returns the builder instance to allow for method chaining.
func (b *TokenConfig) WithStandardClaims(claims jwt.StandardClaims) *TokenConfig {
	b.standardClaims = claims
	return b
}

// WithCustomClaims sets the custom claims for the token.
// Returns the builder instance to allow for method chaining.
func (b *TokenConfig) WithCustomClaims(claims map[string]interface{}) *TokenConfig {
	b.customClaims = claims
	return b
}

// Build builds the token configuration.
// Returns the built configuration instance.
func (b *TokenConfig) Build() TokenConfig {
	return TokenConfig{
		secretKey:      b.secretKey,
		standardClaims: b.standardClaims,
		customClaims:   b.customClaims,
	}
}

// NewAccessTokenConfigBuilder instantiates a new instance of AccessTokenConfig with the provided secret key.
// If the secret key is nil, an error is returned.
func NewAccessTokenConfigBuilder(secretKey []byte) (*TokenConfig, error) {
	return NewTokenConfigBuilder(secretKey)
}

// NewRefreshTokenConfigBuilder instantiates a new instance of RefreshTokenConfig with the provided secret key.
// If the secret key is nil, an error is returned.
func NewRefreshTokenConfigBuilder(secretKey []byte) (*TokenConfig, error) {
	return NewTokenConfigBuilder(secretKey)
}

// NewAuth creates a new Auth instance with the provided access and refresh token configurations.
// The access and refresh token configurations are used to generate and verify tokens.
func NewAuth(options ...func(*Auth)) *Auth {
	auth := &Auth{}

	for _, option := range options {
		option(auth)
	}

	return auth
}

// WithAccessTokenConfig sets the access token configuration on the Auth instance.
// Returns a function that sets the access token configuration.
func WithAccessTokenConfig(config *TokenConfig) func(*Auth) {
	return func(a *Auth) {
		a.AccessConfig = config.Build()
	}
}

// WithRefreshTokenConfig sets the refresh token configuration on the Auth instance.
// Returns a function that sets the refresh token configuration.
func WithRefreshTokenConfig(config *TokenConfig) func(*Auth) {
	return func(a *Auth) {
		a.RefreshConfig = config.Build()
	}
}

// GenerateTokenPair generates a new access and refresh token pair using the configured options.
// Returns the access and refresh tokens, or an error if one occurs.
func (a *Auth) GenerateTokenPair(signingMethod jwt.SigningMethod) (*string, *string, error) {
	accessToken, err := a.GenerateAccessToken(signingMethod)
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err := a.GenerateRefreshToken(signingMethod)
	if err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

// GenerateAccessToken generates a new access token using the configured options.
// Will overwrite any custom claims with the provided standard claims.
// Returns the access token, or an error if one occurs.
func (a *Auth) GenerateAccessToken(signingMethod jwt.SigningMethod) (*string, error) {
	combinedClaims := make(jwt.MapClaims)

	copyCustomClaims(&combinedClaims, a.AccessConfig.customClaims)
	copyStandardClaims(&combinedClaims, a.AccessConfig.standardClaims)

	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims(combinedClaims))
	signedToken, err := token.SignedString(a.AccessConfig.secretKey.Expose())
	if err != nil {
		return nil, err
	}

	return &signedToken, nil
}

// GenerateRefreshToken generates a new refresh token using the configured options.
// Will overwrite any custom claims with the provided standard claims.
// Returns the refresh token, or an error if one occurs.
func (a *Auth) GenerateRefreshToken(signingMethod jwt.SigningMethod) (*string, error) {
	combinedClaims := make(jwt.MapClaims)

	copyCustomClaims(&combinedClaims, a.RefreshConfig.customClaims)
	copyStandardClaims(&combinedClaims, a.RefreshConfig.standardClaims)

	token := jwt.NewWithClaims(signingMethod, combinedClaims)
	signedToken, err := token.SignedString(a.RefreshConfig.secretKey.Expose())
	if err != nil {
		return nil, err
	}

	return &signedToken, nil
}

// verifyToken verifies a token using the provided signing method and secret key.
// Returns the token, or an error if one occurs.
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
// Returns the token, or an error if one occurs.
func (a *Auth) VerifyAccessToken(tokenString string, signingMethod jwt.SigningMethod) (*jwt.Token, error) {
	return a.verifyToken(tokenString, signingMethod, a.AccessConfig.secretKey)
}

// VerifyRefreshToken verifies a refresh token using the configured options.
// Returns the token, or an error if one occurs.
func (a *Auth) VerifyRefreshToken(tokenString string, signingMethod jwt.SigningMethod) (*jwt.Token, error) {
	return a.verifyToken(tokenString, signingMethod, a.RefreshConfig.secretKey)
}

// RefreshAccessToken refreshes the access token using the configured options.
// Returns the new access token, or an error if one occurs.
func (a *Auth) RefreshAccessToken(tokenString string, signingMethod jwt.SigningMethod) (*string, error) {
	token, err := a.VerifyAccessToken(tokenString, signingMethod)
	if err != nil {
		return nil, err
	}

	_, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return a.GenerateAccessToken(signingMethod)
}

// RefreshRefreshToken refreshes the refresh token using the configured options.
// Returns the new refresh token, or an error if one occurs.
func (a *Auth) RefreshRefreshToken(tokenString string, signingMethod jwt.SigningMethod) (*string, error) {
	token, err := a.VerifyRefreshToken(tokenString, signingMethod)
	if err != nil {
		return nil, err
	}

	_, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return a.GenerateRefreshToken(signingMethod)
}

// IsValid checks if a token is valid using the provided signing method and secret key.
// Returns true if the token is valid, otherwise false.
func (a *Auth) IsValid(tokenString string, signingMethod jwt.SigningMethod, secretKey *m.Secret[[]byte]) bool {
	token, err := a.verifyToken(tokenString, signingMethod, secretKey)
	if err != nil {
		return false
	}

	_, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return false
	}

	return token.Valid
}

// copyStandardClaims copies the standard claims from a jwt.StandardClaims instance to a jwt.MapClaims instance.
// It is a utility function used to copy standard claims to the token claims.
func copyStandardClaims(claims *jwt.MapClaims, standardClaims jwt.StandardClaims) {
	claimMapping := map[string]interface{}{
		"exp": standardClaims.ExpiresAt,
		"iss": standardClaims.Issuer,
		"aud": standardClaims.Audience,
		"iat": standardClaims.IssuedAt,
		"nbf": standardClaims.NotBefore,
		"sub": standardClaims.Subject,
		"jti": standardClaims.Id,
	}

	for key, value := range claimMapping {
		if intValue, ok := value.(int64); ok && intValue != 0 {
			(*claims)[key] = value
		} else if strValue, ok := value.(string); ok && strValue != "" {
			(*claims)[key] = value
		}
	}
}

// copyCustomClaims copies the custom claims from a map[string]interface{} instance to a jwt.MapClaims instance.
// It is a utility function used to copy custom claims to the token claims.
func copyCustomClaims(claims *jwt.MapClaims, customClaims map[string]interface{}) {
	for key, value := range customClaims {
		(*claims)[key] = value
	}
}
