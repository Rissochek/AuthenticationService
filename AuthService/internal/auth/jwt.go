package auth

import (
	"fmt"
	"strings"
	"time"

	"AuthService/internal/model"
	"AuthService/source/utils"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

type AuthManager interface {
	GenerateToken(user *model.User, session_id uint) (string, error)
	VerifyToken(user_token string, exparation_check bool) (*TokenClaims, error)
}

type TokenClaims struct {
	GUID      string
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
		GUID:      user.GUID,
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
		if validation_error, ok := err.(*jwt.ValidationError); ok {
			if validation_error.Errors&jwt.ValidationErrorSignatureInvalid != 0{
				return nil, fmt.Errorf("invalid signature")
			}

			if validation_error.Errors&jwt.ValidationErrorExpired != 0 {
				if exparation_check {
					return nil, fmt.Errorf("token expired")
				}
				
				claims, ok := token.Claims.(*TokenClaims)
				if !ok {
					return nil, fmt.Errorf("invalid token claims")
				}
			
				return claims, nil
			}
		}
		log.Errorf("invalid token: %v", err)
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
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
