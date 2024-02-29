package hydrate

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

var secretKey = []byte("secret")

func compareTokens(t1, t2 []byte) (bool, error) {
	token1, err := jwt.Parse(string(t1), func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return false, err
	}

	token2, err := jwt.Parse(string(t2), func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return false, err
	}

	claims1, ok := token1.Claims.(jwt.MapClaims)
	if !ok || !token1.Valid {
		return false, fmt.Errorf("invalid token")
	}

	claims2, ok := token2.Claims.(jwt.MapClaims)
	if !ok || !token2.Valid {
		return false, fmt.Errorf("invalid token")
	}

	return compareClaims(claims1, claims2), nil
}

func compareClaims(c1, c2 jwt.MapClaims) bool {
	delete(c1, "exp")
	delete(c2, "exp")

	return reflect.DeepEqual(c1, c2)
}

func setupToken(t *testing.T) ([]byte, *TokenConfig, error) {
	secretKey := secretKey
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Issuer:    "test",
		Audience:  "test",
	}

	tokenConfig, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(claims),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	token, err := tokenConfig.GenerateToken()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	return token, tokenConfig, nil
}

func setupTokens(t *testing.T) (*TokenConfig, *TokenConfig, error) {
	accessClaims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Issuer:    "test",
		Audience:  "test",
	}

	refreshClaims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}

	accessConfig, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(accessClaims),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	refreshConfig, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(refreshClaims),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	return accessConfig, refreshConfig, nil
}

func TestValidNewToken(t *testing.T) {
	_, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(jwt.StandardClaims{
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			Issuer:    "test",
			Audience:  "test",
		}),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestMissingSecretKey(t *testing.T) {
	_, err := NewToken()

	if err != ErrInvalidSecretKey {
		t.Errorf("Expected error: %v, got: %v", ErrInvalidSecretKey, err)
	}
}

func TestMissingStandardClaims(t *testing.T) {
	_, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(jwt.StandardClaims{}),
	)

	if err != ErrInvalidTokenConfig {
		t.Errorf("Expected error: %v, got: %v", ErrInvalidTokenConfig, err)
	}
}

func TestMissingExpiresAt(t *testing.T) {
	_, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(jwt.StandardClaims{
			Issuer:   "test",
			Audience: "test",
		}),
	)

	if err != ErrInvalidTokenConfig {
		t.Errorf("Expected error: %v, got: %v", ErrInvalidTokenConfig, err)
	}
}

func TestValidGenerateTokenPair(t *testing.T) {
	accessConfig, refreshConfig, err := setupTokens(t)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	accessToken, refreshToken, err := GenerateTokenPair(accessConfig, refreshConfig)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if accessToken == nil || refreshToken == nil {
		t.Errorf("Failed to generate token pair")
	}

	same, err := compareTokens(accessToken, refreshToken)
	if err != nil {
		t.Errorf("Unexpected error comparing tokens: %v", err)
	}

	if same {
		t.Errorf("Expected tokens to be different")
	}
}

func TestInvalidGenerateTokenPair(t *testing.T) {
	_, _, err := GenerateTokenPair(nil, nil)

	if err != ErrTokenConfigNil {
		t.Errorf("Expected error: %v, got: %v", ErrTokenConfigNil, err)
	}
}

func TestValidGenerateToken(t *testing.T) {
	token, _, err := setupToken(t)
	if err != nil {
		return
	}

	if token == nil {
		t.Errorf("Failed to generate token")
	}
}

func TestValidRegenerateToken(t *testing.T) {
	token, config, err := setupToken(t)
	if err != nil {
		return
	}

	time.Sleep(1 * time.Second)

	newToken, err := config.GenerateToken()
	if err != nil {
		t.Errorf("Unexpected error regenerating token: %v", err)
	}

	same, err := compareTokens(token, newToken)
	if err != nil {
		t.Errorf("Unexpected error comparing tokens: %v", err)
	}

	if !same {
		t.Errorf("Expected tokens to be the same")
	}
}

func TestValidRefreshToken(t *testing.T) {
	access_config, refresh_config, err := setupTokens(t)
	if err != nil {
		return
	}

	// Generate tokens
	access_token, _, err := GenerateTokenPair(access_config, refresh_config)
	if err != nil {
		t.Errorf("Unexpected error generating token pair: %v", err)
	}

	time.Sleep(2 * time.Second)

	newToken, err := access_config.RefreshToken(refresh_config)
	if err != nil {
		t.Errorf("Unexpected error refreshing token: %v", err)
	}

	if newToken == nil {
		t.Errorf("Failed to refresh token")
	}

	if string(access_token) == string(newToken) {
		t.Errorf("Expected tokens to be different")
	}
}

func TestInvalidRefreshToken(t *testing.T) {
	_, err := (&TokenConfig{}).RefreshToken(nil)

	if err != ErrTokenNotGenerated {
		t.Errorf("Expected error: %v, got: %v", ErrTokenNotGenerated, err)
	}
}

func TestValidExtractClaims(t *testing.T) {
	_, config, err := setupToken(t)
	if err != nil {
		return
	}

	claims, err := config.ExtractClaims()
	if err != nil {
		t.Errorf("Unexpected error extracting claims: %v", err)
	}

	assertClaims := jwt.MapClaims{
		"iss": "test",
		"aud": "test",
	}

	if claims["iss"] != assertClaims["iss"] {
		t.Errorf("Expected iss to be %v, got %v", assertClaims["iss"], claims["iss"])
	}

	if claims["aud"] != assertClaims["aud"] {
		t.Errorf("Expected aud to be %v, got %v", assertClaims["aud"], claims["aud"])
	}
}

func TestInvalidExtractClaims(t *testing.T) {
	_, err := (&TokenConfig{}).ExtractClaims()

	if err != ErrTokenNotGenerated {
		t.Errorf("Expected error: %v, got: %v", ErrTokenNotGenerated, err)
	}
}

func TestInvalidExtractClaimsFromInvalidExperation(t *testing.T) {
	access_config, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(jwt.StandardClaims{
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			Issuer:    "test",
			Audience:  "test",
		}),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	_, err = access_config.GenerateToken()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	_, err = access_config.ExtractClaims()

	if err != ErrTokenInvalid {
		t.Errorf("Expected error: %v, got: %v", ErrTokenInvalid, err)
	}
}

func TestValidIsValid(t *testing.T) {
	_, config, err := setupToken(t)
	if err != nil {
		return
	}

	valid := config.IsValid()

	if !valid {
		t.Errorf("Expected token to be valid")
	}
}

func TestInvalidIsValid(t *testing.T) {
	access_config, err := NewToken(
		SecretKey(secretKey),
		WithStandardClaims(jwt.StandardClaims{
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			Issuer:    "test",
			Audience:  "test",
		}),
	)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	_, err = access_config.GenerateToken()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	valid := access_config.IsValid()

	if valid {
		t.Errorf("Expected token to be invalid")
	}
}

func TestParseToken(t *testing.T) {
	_, config, err := setupToken(t)
	if err != nil {
		return
	}

	parsedToken, err := config.ParseToken()
	if err != nil {
		t.Errorf("Unexpected error parsing token: %v", err)
	}

	if parsedToken != nil {
		expected := jwt.MapClaims{
			"iss": "test",
			"aud": "test",
		}

		same := compareClaims(parsedToken.Claims.(jwt.MapClaims), expected)

		if err != nil {
			t.Errorf("Unexpected error comparing tokens: %v", err)
		}

		if !same {
			t.Errorf("Expected tokens to be the same")
		}
	} else {
		t.Errorf("parsedToken is nil")
	}
}

func TestCopyStandardClaims(t *testing.T) {
	claims := jwt.MapClaims{}
	standardClaims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Issuer:    "test issuer",
		Audience:  "test audience",
		Subject:   "test subject",
		Id:        "test ID",
		NotBefore: time.Now().Add(-time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	copyStandardClaims(&claims, standardClaims)

	if !reflect.DeepEqual(claims["exp"], standardClaims.ExpiresAt) {
		t.Error("Exp claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["iss"], standardClaims.Issuer) {
		t.Error("Iss claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["aud"], standardClaims.Audience) {
		t.Error("Aud claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["sub"], standardClaims.Subject) {
		t.Error("Sub claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["jti"], standardClaims.Id) {
		t.Error("Jti claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["nbf"], standardClaims.NotBefore) {
		t.Error("Nbf claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["iat"], standardClaims.IssuedAt) {
		t.Error("Iat claim not copied correctly")
	}
}

func TestCopyCustomClaims(t *testing.T) {
	claims := jwt.MapClaims{}
	customClaims := map[string]interface{}{
		"name":  "John Doe",
		"admin": true,
	}

	copyCustomClaims(&claims, customClaims)

	if !reflect.DeepEqual(claims["name"], customClaims["name"]) {
		t.Error("Custom name claim not copied correctly")
	}
	if !reflect.DeepEqual(claims["admin"], customClaims["admin"]) {
		t.Error("Custom admin claim not copied correctly")
	}
}

func TestCopyClaims(t *testing.T) {
	claims := jwt.MapClaims{}
	standardClaims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	customClaims := map[string]interface{}{
		"name": "John Doe",
	}

	copyClaims(&claims, standardClaims, customClaims)

	if !reflect.DeepEqual(claims["exp"], standardClaims.ExpiresAt) {
		t.Error("Exp claim not copied")
	}
	if !reflect.DeepEqual(claims["name"], customClaims["name"]) {
		t.Error("Custom name claim not copied")
	}
}
