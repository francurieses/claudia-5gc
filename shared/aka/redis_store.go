package aka

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	authKeyPrefix = "ausf:auth:"
	// authTTL matches the VerifyRES 5-minute expiry check (TS 29.509 §5.7).
	authTTL = 5 * time.Minute
)

// RedisStore stores auth contexts in Redis with TTL-based expiry.
// Replaces in-memory Store for multi-instance AUSF deployments.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore connects to Redis and returns a RedisStore.
func NewRedisStore(addr string) (*RedisStore, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("ausf redis: ping %s: %w", addr, err)
	}
	return &RedisStore{client: rdb}, nil
}

func (s *RedisStore) Put(id string, ctx *AuthContext) {
	js, err := json.Marshal(ctx)
	if err != nil {
		return
	}
	_ = s.client.Set(context.Background(), authKeyPrefix+id, js, authTTL).Err()
}

func (s *RedisStore) Get(id string) (*AuthContext, bool) {
	js, err := s.client.Get(context.Background(), authKeyPrefix+id).Bytes()
	if err != nil {
		return nil, false
	}
	var ctx AuthContext
	if err := json.Unmarshal(js, &ctx); err != nil {
		return nil, false
	}
	return &ctx, true
}

func (s *RedisStore) Delete(id string) {
	_ = s.client.Del(context.Background(), authKeyPrefix+id).Err()
}

// Close releases the Redis connection.
func (s *RedisStore) Close() error { return s.client.Close() }
