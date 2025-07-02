package utils

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/metadata"
)

func GetFromMetadata(ctx context.Context, key string) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Errorf("failed to get header from metadata. key: %v", key)
		return "", fmt.Errorf("failed to get header from metadata. key: %v", key)
	}

	token := md.Get(key)[0]
	return token, nil
}