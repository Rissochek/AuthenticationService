package model

import (
	"github.com/golang-jwt/jwt"
)

type TokenClaims struct {
	GUID string
	jwt.StandardClaims
}