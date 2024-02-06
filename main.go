package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

func main() {
	auth := NewAuth(
		WithAccessTokenConfig("access_secret", time.Minute*15),
		WithRefreshTokenConfig("refresh_secret", time.Hour*24),
	)

	// Example usage
	accessClaims := jwt.MapClaims{
		"authorized": true,
		"exp":        time.Now().Add(time.Minute * 15).Unix(),
		"iat":        time.Now().Unix(),
	}

	accessToken, err := auth.GenerateToken(accessClaims, tokenTypeAccess)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(*accessToken)

	refreshClaims := jwt.MapClaims{
		"exp":        time.Now().Add(time.Hour * 24).Unix(),
		"iat":        time.Now().Unix(),
	}

	accessToken, refreshToken, err := auth.GenerateTokenPair(accessClaims, refreshClaims)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(*refreshToken)
	fmt.Println(*accessToken)
}
