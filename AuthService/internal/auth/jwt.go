package auth

import (
	"fmt"
	"strings"
	"time"

	"AuthService/internal/model"
	"AuthService/internal/utils"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

type TokenClaims struct {
	GUID string
	SessionId uint
	jwt.StandardClaims
}

type JWTManager struct {
	SecretKey     string
	TokenDuration time.Duration
}

func NewJWTManager(token_duration time.Duration) *JWTManager {
	secret := utils.GetKeyFromEnv("SECRET_KEY")
	return &JWTManager{TokenDuration: token_duration, SecretKey: secret}
}

func (manager *JWTManager) GenerateToken(user *model.User, session_id uint) (string, error) {
	claims := TokenClaims{
		GUID: user.GUID,
		SessionId: session_id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.TokenDuration).Unix()},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed_string, err := token.SignedString([]byte(manager.SecretKey))
	if err != nil {
		log.Errorf("failed to generate access token: %v", err)
		return "", nil
	}

	return signed_string, nil
}

func (manager *JWTManager) VerifyToken(user_token string, exparation_check bool) (*TokenClaims, error) {
	user_token, err := ExtractToken(user_token)
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseWithClaims(
		user_token,
		&TokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			_, ok := t.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				log.Errorf("failed to verify token: %v", err)
				return nil, fmt.Errorf("wrong jwt encrypting method")
			}

			return []byte(manager.SecretKey), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	if exparation_check{
		if claims.ExpiresAt < time.Now().Unix() {
			return nil, fmt.Errorf("token has expired")
		}
	}
	
	return claims, nil
}

func ExtractToken(bearerToken string) (string, error) {
	if !strings.HasPrefix(bearerToken, "Bearer ") {
		return "", fmt.Errorf("invalid token format")
	}

	token := strings.TrimPrefix(bearerToken, "Bearer ")
	return token, nil
}
