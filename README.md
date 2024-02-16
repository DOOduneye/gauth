# 

## A simple JWT authentication utility for Go

[![GAuth Go Report](https://goreportcard.com/badge/github.com/DOOduneye/gauth)](https://goreportcard.com/report/github.com/DOOduneye/gauth)
[![MIT License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/license/mit/)
[![Go.Dev Reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/DOOduneye/gauth)


## Table of Contents
- [Installation](#installation)
- [Features](#features)
- [Usage](#usage)

## Installation
```bash
go get github.com/DOOduneye/gauth
```

## Features
- [x] Generate Access and Refresh Tokens
- [x] Verify Access and Refresh Tokens
- [x] Set Custom Claims and Standard Claims
- [ ] Expire Tokens
- [ ] Middleware for Gin and Echo
- [ ] Token Blacklisting / Revoking
- [ ] Testing

## Usage
```go
package main

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/DOOduneye/gauth"
)


func main() {
	accessTokenExp := time.Now().Add(1 * time.Hour).Unix()
	refreshTokenExp := time.Now().Add(24 * time.Hour).Unix()

	access, err := NewAccessTokenConfigBuilder([]byte("secret"))
	if err != nil {
		panic(err)
	}
	access.WithStandardClaims(jwt.StandardClaims{
		ExpiresAt: accessTokenExp,
		Issuer:    "test",
		Audience:  "test",
	})
	access.WithCustomClaims(map[string]interface{}{
		"role": "admin",
	})

	refresh, err := NewRefreshTokenConfigBuilder([]byte("secret"))
	if err != nil {
		panic(err)
	}

	refresh.WithStandardClaims(jwt.StandardClaims{
		ExpiresAt: refreshTokenExp,
	})

	auth := NewAuth(
		WithAccessTokenConfig(access),
		WithRefreshTokenConfig(refresh),
	)

	accessToken, err := auth.GenerateAccessToken(jwt.SigningMethodHS256)
	if err != nil {
		panic(err)
	}

	refreshToken, err := auth.GenerateRefreshToken(jwt.SigningMethodHS256)
	if err != nil {
		panic(err)
	}

	accessClaims, err := auth.VerifyAccessToken(*accessToken, jwt.SigningMethodHS256)
	if err != nil {
		panic(err)
	}

	refreshClaims, err := auth.VerifyRefreshToken(*refreshToken, jwt.SigningMethodHS256)
	if err != nil {
		panic(err)
	}

	fmt.Println(*accessToken)
	fmt.Println(*refreshToken)

	fmt.Println(accessClaims)
	fmt.Println(refreshClaims)
}
```