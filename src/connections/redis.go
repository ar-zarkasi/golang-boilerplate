package connections

import (
	"context"
	"log"
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
	ClearPattern(pattern string) error
}

type redisWrapper struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedis(cfg types.MainConfig) Redis {
	client := redis.NewClient(&redis.Options{
		Addr:             cfg.Redis.Host + ":" + strconv.Itoa(cfg.Redis.Port),
		Password:         cfg.Redis.Password,
		DB:               cfg.Redis.DB,
		DisableIndentity: true, // Disable client info for Redis < 7.2 compatibility
	})

	log.Printf("Redis Connected to host tcp://%s", client.Options().Addr)
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

func (r *redisWrapper) ClearPattern(pattern string) error {
	// Use SCAN to find all keys matching the pattern
	var cursor uint64
	var deletedCount int

	for {
		keys, nextCursor, err := r.client.Scan(r.ctx, cursor, pattern, 100).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			// Delete the keys found
			if err := r.client.Del(r.ctx, keys...).Err(); err != nil {
				return err
			}
			deletedCount += len(keys)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	log.Printf("Cleared %d keys matching pattern: %s", deletedCount, pattern)
	return nil
}
