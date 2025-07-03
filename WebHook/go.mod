module Webhook

go 1.23.3

require AuthService v0.0.0

require (
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	google.golang.org/grpc v1.73.0 // indirect
)

replace AuthService => ../AuthService
