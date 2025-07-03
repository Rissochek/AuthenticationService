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

	tokens := md.Get(key)
	if len(tokens) != 0 {
		token := tokens[0]
		return token, nil
	}

	log.Errorf("%v is not provided in metadata", key)
	return "", fmt.Errorf("%v is not provided in metadata", key)
}
