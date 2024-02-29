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
//	"github.com/dooduneye/hydrate"
//
// )
//
//	func main() {
//		access_config, err := hydrate.NewToken(
//			WithStandardClaims(jwt.StandardClaims{
//				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
//				Issuer:    "test",
//				Audience:  "test",
//			}),
//			WithCustomClaims(map[string]interface{}{
//				"role": "admin",
//			}),
//			SecretKey([]byte("access_secret")),
//		)
//
//		if err != nil {
//			fmt.Println(err)
//			return
//		}
//
//		refresh_config, err := hydrate.NewToken(
//			WithStandardClaims(jwt.StandardClaims{
//				ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
//			}),
//			SecretKey([]byte("refresh_secret")),
//		)
//
//		if err != nil {
//			fmt.Println(err)
//			return
//		}
//
//		accessToken, refreshToken, err := hydrate.GenerateTokenPair(access_config, refresh_config)
//		if err != nil {
//			fmt.Println(err)
//			return
//		}
//
//		fmt.Println("Access Token:", string(accessToken))
//		fmt.Println("Refresh Token:", string(refreshToken))
//	}
package hydrate

import (
	"time"

	m "github.com/garrettladley/mattress"
	"github.com/golang-jwt/jwt"
)

// TokenConfig defines the configuration for tokens.
// These include the secret key, standard claims, and custom claims.
type TokenConfig struct {
	secretKey      *m.Secret[[]byte]      // Secret key used to sign the token
	signingMethod  jwt.SigningMethod      // Signing method used to sign the token
	standardClaims jwt.StandardClaims     // Standard claims for the token
	customClaims   map[string]interface{} // Custom claims for the token
	token          *string                // Token generated using the configuration
	expiration     time.Duration          // Expiration time for the token
}

// NewToken instantiates a new instance of TokenConfig with the provided options.
// If the secret key is nil, an error is returned.
func NewToken(options ...func(*TokenConfig) error) (*TokenConfig, error) {
	token := &TokenConfig{
		signingMethod: jwt.SigningMethodHS256,
	}

	var err error
	for _, option := range options {
		err = option(token)
		if err != nil {
			return nil, ErrInvalidTokenConfig
		}
	}

	if token.secretKey == nil {
		return nil, ErrInvalidSecretKey
	}

	return token, nil
}

// SecretKey sets the secret key for the token.
// If the secret key is nil, an error is returned.
func SecretKey(key []byte) func(*TokenConfig) error {
	return func(t *TokenConfig) error {
		secretKey, err := m.NewSecret(key)
		if err != nil {
			return ErrInvalidSecretKey
		}

		t.secretKey = secretKey
		return nil
	}
}

// WithSigningMethod sets the signing method for the token.
// If you don't call this function, the default signing method is HS256.
func WithSigningMethod(method jwt.SigningMethod) func(*TokenConfig) error {
	return func(t *TokenConfig) error {
		if method == nil {
			return ErrSigningMethodNil
		}

		t.signingMethod = method
		return nil
	}
}

// WithStandardClaims optionally sets the standard claims for the token.
// Requires the expiration time to be set.
func WithStandardClaims(claims jwt.StandardClaims) func(*TokenConfig) error {
	return func(t *TokenConfig) error {
		if claims.ExpiresAt == 0 {
			return ErrStandardClaimMissing
		}

		t.standardClaims = claims
		t.expiration = time.Duration(claims.ExpiresAt-time.Now().Unix()) * time.Second
		return nil
	}
}

// WithCustomClaims optionally sets the custom claims for the token.
func WithCustomClaims(claims map[string]interface{}) func(*TokenConfig) error {
	return func(t *TokenConfig) error {
		if len(claims) == 0 {
			return ErrCustomClaimsMissing
		}

		t.customClaims = claims
		return nil
	}
}

// GenerateTokenPair generates a new access and refresh token pair using the configured options.
// Returns the access and refresh tokens, or an error if one occurs.
func GenerateTokenPair(accessConfig, refreshConfig *TokenConfig) ([]byte, []byte, error) {
	if accessConfig == nil || refreshConfig == nil {
		return nil, nil, ErrTokenConfigNil
	}

	accessToken, err := accessConfig.GenerateToken()
	if err != nil {
		return nil, nil, err
	}

	refreshToken, err := refreshConfig.GenerateToken()
	if err != nil {
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

// GenerateToken generates a new token using the configured options.
// Will overwrite any custom claims with the provided standard claims.
// Returns the access token, or an error if one occurs.
func (t *TokenConfig) GenerateToken() ([]byte, error) {
	if t.token != nil {
		return t.regenerateToken()
	}

	combinedClaims := make(jwt.MapClaims)

	copyClaims(&combinedClaims, t.standardClaims, t.customClaims)

	token := jwt.NewWithClaims(t.signingMethod, jwt.MapClaims(combinedClaims))
	signedToken, err := token.SignedString(t.secretKey.Expose())
	if err != nil {
		return nil, ErrSigningToken
	}

	t.token = &signedToken

	return []byte(signedToken), nil
}


// regenerateToken generates a new token using the configured options.
// Returns the token, or an error if one occurs.
func (t *TokenConfig) regenerateToken() ([]byte, error) {
	if t.token == nil {
		return nil, ErrTokenNotGenerated
	}

	token, err := t.ParseToken()
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrClaimsInvalid
	}

	claims = t.updateExpiration(claims)
	claims = t.updateIssuedAt(claims)

	token = jwt.NewWithClaims(t.signingMethod, claims)
	signedToken, err := token.SignedString(t.secretKey.Expose())
	if err != nil {
		return nil, ErrSigningToken
	}

	t.token = &signedToken

	return []byte(signedToken), nil
}

// updateExpiration updates the expiration claim of the token.
// If the expiration claim is not present, it won't be added.
func (t *TokenConfig) updateExpiration(claims jwt.MapClaims) jwt.MapClaims {
	if _, ok := claims["exp"]; ok {
		claims["exp"] = time.Now().Add(t.expiration).Unix()
	}
	return claims
}

// updateIssuedAt updates the issued at claim of the token.
// If the issued at claim is not present, it won't be added.
func (t *TokenConfig) updateIssuedAt(claims jwt.MapClaims) jwt.MapClaims {
	if _, ok := claims["iat"]; ok {
		claims["iat"] = time.Now().Unix()
	}
	return claims
}

// RefreshToken takes a refresh config and generates a new access token using the configured options.
// Returns the access token, or an error if one occurs.
func (t *TokenConfig) RefreshToken(refreshConfig *TokenConfig) ([]byte, error) {
	if t.token == nil || refreshConfig == nil {
		return nil, ErrTokenNotGenerated
	}

	isValid := refreshConfig.IsValid()

	if !isValid {
		return nil, ErrTokenInvalid
	}

	accessToken, err := t.GenerateToken()
	if err != nil {
		return nil, err
	}

	return accessToken, nil
}

// ExtractClaims extracts the claims from the token using the configured options.
// Returns the claims, or an error if one occurs.
func (t *TokenConfig) ExtractClaims() (jwt.MapClaims, error) {
	if t.token == nil {
		return nil, ErrTokenNotGenerated
	}

	token, err := t.ParseToken()
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrClaimsInvalid
	}

	return claims, nil
}

// IsValid checks if the token is valid using the configured options.
// Returns true if the token is valid, or false if it is not.
func (t *TokenConfig) IsValid() bool {
	if t.token == nil {
		return false
	}

	token, err := t.ParseToken()
	if err != nil {
		return false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	if !token.Valid {
		return false
	}

	if _, ok := claims["exp"]; ok {
		if int64(claims["exp"].(float64)) < time.Now().Unix() {
			return false
		}
	}

	return true
}

// ParseToken parses the token using the configured options.
// Returns the token, or an error if one occurs.
func (t *TokenConfig) ParseToken() (*jwt.Token, error) {
	token, err := jwt.Parse(*t.token, func(token *jwt.Token) (interface{}, error) {
		return t.secretKey.Expose(), nil
	})

	if err != nil {
		return nil, ErrTokenInvalid
	}

	return token, nil
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

// copyClaims copies the standard and custom claims to the token claims.
// It is a utility function used to copy claims to the token claims.
func copyClaims(claims *jwt.MapClaims, standardClaims jwt.StandardClaims, customClaims map[string]interface{}) {
	copyCustomClaims(claims, customClaims)
	copyStandardClaims(claims, standardClaims)
}
