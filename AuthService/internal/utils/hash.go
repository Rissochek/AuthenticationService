package utils

import (
	"log"

	"golang.org/x/crypto/bcrypt"
)

func GenerateHash(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to generate hash: %v", err)
	}
	return string(hash)
}

func CompareHashAndPassword(password string, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err
}
