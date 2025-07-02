package auth

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	log "github.com/sirupsen/logrus"
)

type RefreshManager interface {
	GenerateRefreshToken() (string, error)
	GetExparationTime() time.Duration
}

type refresh_generator struct {
	RefreshLength  int64
	ExparationTime time.Duration
}

func NewRefreshGenerator(refresh_length int64, exparation_time time.Duration) *refresh_generator {
	refresh_generator := refresh_generator{RefreshLength: refresh_length, ExparationTime: exparation_time}
	return &refresh_generator
}

func (generator *refresh_generator) GenerateRefreshToken() (string, error) {
	bytes := make([]byte, generator.RefreshLength)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Errorf("failed to generate refresh token: %v", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func (generator *refresh_generator) GetExparationTime() time.Duration {
	return generator.ExparationTime
}
