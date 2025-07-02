package auth

import (
	"crypto/rand"
	"encoding/base64"

	log "github.com/sirupsen/logrus"
)

type refresh_generator struct {
	RefreshLength int64
}

func NewRefreshGenerator(refresh_length *int64) *refresh_generator {
	refresh_generator := refresh_generator{RefreshLength: *refresh_length}
	return &refresh_generator
}

func (generator *refresh_generator) GenerateRefresh() (string, error) {
	bytes := make([]byte, generator.RefreshLength)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Errorf("failed to generate refresh token: %v", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
