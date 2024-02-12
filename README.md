<h1 align="center">gauth</h1>

<h2 align="center">Simple wrapper over <code>jwt-go</code> for Generate authentication flow</h2>

<div align="center">
  <a href="https://goreportcard.com/report/github.com/DOOduneye/gauth">
    <img src="https://goreportcard.com/badge/github.com/DOOduneye/gauth"
      alt="GAuth Go Report" />
  </a>
  <a href="https://opensource.org/license/mit/">
    <img src="https://img.shields.io/badge/license-MIT-blue"
      alt="MIT License" />
  </a>
  <a href="https://pkg.go.dev/github.com/DOOduneye/gauth">
    <img src="https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white"
      alt="Go.Dev Reference" />
  </a>
</div>

## Usage
```go
package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

func main() {
	auth := NewAuth(
		WithAccessTokenConfig("access_secret"),
		WithRefreshTokenConfig("refresh_secret"),
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
```