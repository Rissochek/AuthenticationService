package annotators

import (
	"context"
	"net/http"

	"google.golang.org/grpc/metadata"
)

func PutClientUserAgentInMetadata(ctx context.Context, request *http.Request) metadata.MD {
	user_agent := request.Header.Get("User-Agent")
	if user_agent != "" {
		return metadata.Pairs("x-user-agent", user_agent)
	}

	return nil
}