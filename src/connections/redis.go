package connections

import (
	"context"
	"strconv"
	"time"

	"app/src/types"

	"github.com/redis/go-redis/v9"
)

type Redis interface {
	Client() *redis.Client
	Ping() error
	Set(key string, value interface{}, expiration time.Duration) error
	Get(key string) (string, error)
	Clear(key string) error
}

type redisWrapper struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedis(cfg types.MainConfig) Redis {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Host + ":" + strconv.Itoa(cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	return &redisWrapper{
		client: client,
		ctx:    context.Background(),
	}
}

func (r *redisWrapper) Client() *redis.Client {
	return r.client
}

func (r *redisWrapper) Ping() error {
	return r.client.Ping(r.ctx).Err()
}

func (r *redisWrapper) Set(key string, value any, expiration time.Duration) error {
	return r.client.Set(r.ctx, key, value, expiration).Err()
}

func (r *redisWrapper) Get(key string) (string, error) {
	return r.client.Get(r.ctx, key).Result()
}

func (r *redisWrapper) Clear(key string) error {
	return r.client.Del(r.ctx, key).Err()
}
