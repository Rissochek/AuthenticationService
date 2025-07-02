package database

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"

	"AuthService/internal/auth"
	"AuthService/source/utils"
)

type BlacklistManager interface {
	AddToBlacklist(token string, expiry int64, ctx context.Context) error
	BlacklistCheck(ctx context.Context, token string) (bool, error)
}

type redis_manager struct {
	RedisClient *redis.Client
}

func NewRedisManager() *redis_manager {
	redis_host := utils.GetKeyFromEnv("REDIS_HOST")
	redis_port := utils.GetKeyFromEnv("REDIS_PORT")
	redis_password := utils.GetKeyFromEnv("REDIS_PASSWORD")
	redis_db_num, err := strconv.Atoi(utils.GetKeyFromEnv("REDIS_DB"))
	if err != nil {
		log.Fatalf("invalid redis_db_num: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%v:%v", redis_host, redis_port),
		Password: fmt.Sprintf("%v", redis_password),
		DB:       redis_db_num,
	})

	return &redis_manager{RedisClient: client}
}

func (redis_manager *redis_manager) AddToBlacklist(token string, expiry int64, ctx context.Context) error {
	exparation_time := time.Duration(expiry-time.Now().Unix()) * time.Second
	if err := redis_manager.RedisClient.Set(ctx, token, "revoked", exparation_time); err.Err() != nil {
		log.Errorf("failed to add token to blacklist: %v", err.Err())
		return err.Err()
	}

	return nil
}

//bool values is {false: not blacklisted, true: blacklisted}
func (redis_manager *redis_manager) BlacklistCheck(ctx context.Context, token string) (bool, error) {
	user_token, err := auth.ExtractToken(token)
	if err != nil {
		log.Errorf("failed to extract token: %v", err)
		return false, err
	}
	result, err := redis_manager.RedisClient.Get(ctx, user_token).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil{
		log.Errorf("failed to get token: %v", err)
		return false, fmt.Errorf("failed to check token blacklisted")
	}
	if result == "revoked" {
		return true, nil
	}

	return false, nil
}
