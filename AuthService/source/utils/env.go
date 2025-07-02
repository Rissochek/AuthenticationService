package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvFile() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("no .env file found") //if u have this error, but .env file is existing then try to execute with this command go run .\cmd\server\main.go
	}
}

func GetKeyFromEnv(key string) string {
	secret, exists := os.LookupEnv(key)
	if !exists {
		log.Fatalf("%v value is not set in .env file.", key)
	}
	return secret
}
