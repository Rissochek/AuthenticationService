module Gateway

go 1.23.3

require (
	AuthService v0.0.0
	Proto v0.0.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.1
	google.golang.org/grpc v1.73.0
)

require (
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace Proto => ../Proto

replace AuthService => ../AuthService
