package annotators

import (
	"context"
	"log"
	"net/http"

	"google.golang.org/grpc/metadata"
)

func PutClientUserAgentInMetadata(ctx context.Context, request *http.Request) metadata.MD {
	user_agent := request.Header.Get("User-Agent")
	log.Printf("User-Agent is %v", user_agent)
	if user_agent != "" {
		return metadata.Pairs("x-user-agent", user_agent)
	}

	return nil
}