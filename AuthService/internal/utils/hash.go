package utils

import (
	"golang.org/x/crypto/bcrypt"
	log "github.com/sirupsen/logrus"
)

func GenerateHash(password string) (string, error){
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("failed to generate hash: %v", err)
		return "", err
	}
	return string(hash), nil
}

func CompareHashAndPassword(password string, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err
}
