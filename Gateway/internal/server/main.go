package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"AuthService/source/utils"
	"Gateway/internal/annotators"

	pb "Proto"
)



func main(){
	utils.LoadEnvFile()

	auth_host := utils.GetKeyFromEnv("AUTH_HOST_NAME")
	auth_port := utils.GetKeyFromEnv("AUTH_HOST_PORT")
	gw_host := utils.GetKeyFromEnv("GATEWAY_HOST_NAME")
	gw_port := utils.GetKeyFromEnv("GATEWAY_HOST_PORT")

	grpc_auth_address := fmt.Sprintf("%v:%v", auth_host, auth_port)
	http_address := fmt.Sprintf("%v:%v", gw_host, gw_port)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux(runtime.WithMetadata(annotators.PutClientIpInMetadata), runtime.WithMetadata(annotators.PutClientUserAgentInMetadata))
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err := pb.RegisterAuthHandlerFromEndpoint(ctx, mux, grpc_auth_address, opts)
	if err != nil{
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
	
	log.Printf("HTTP server listening on %s", http_address)
    log.Fatal(http.ListenAndServe(http_address, mux))
}