package annotators

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

func PutClientIpInMetadata (ctx context.Context, request *http.Request) metadata.MD{
	header := request.Header.Get("X-Forwarded-For")
	ips := strings.Split(header, ",")
	if len(ips) > 0 {
		client_ip := ips[0]
		return metadata.Pairs("x-forwarded-for", client_ip)
	}
	
	client_ip := request.RemoteAddr
	return metadata.Pairs("x-forwarded-for", client_ip)
} 
