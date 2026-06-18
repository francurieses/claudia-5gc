package store

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

const keyTMSISeq = "amf:seq:tmsi"

// RedisCache implements Cache using Redis atomic counters.
// The TMSI counter persists across AMF restarts as long as Redis is running.
// SeedTMSIIfLower must be called at startup to avoid TMSI reuse after Redis restarts.
type RedisCache struct {
	client *redis.Client
}

// NewRedisCache connects to Redis at the given address (host:port).
func NewRedisCache(addr string) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("amf cache: redis ping %s: %w", addr, err)
	}
	return &RedisCache{client: rdb}, nil
}

// SeedTMSIIfLower sets amf:seq:tmsi to minVal if the current value is lower.
// This protects against TMSI reuse after Redis is restarted with an empty store.
func (c *RedisCache) SeedTMSIIfLower(ctx context.Context, minVal uint32) error {
	// Lua script: atomic compare-and-set
	script := redis.NewScript(`
		local cur = tonumber(redis.call("GET", KEYS[1])) or 0
		if tonumber(ARGV[1]) > cur then
			redis.call("SET", KEYS[1], ARGV[1])
		end
		return redis.status_reply("OK")
	`)
	if err := script.Run(ctx, c.client, []string{keyTMSISeq}, minVal).Err(); err != nil {
		return fmt.Errorf("amf cache: SeedTMSIIfLower: %w", err)
	}
	return nil
}

// NextTMSI atomically increments and returns the next 5G-TMSI.
func (c *RedisCache) NextTMSI(ctx context.Context) (uint32, error) {
	v, err := c.client.Incr(ctx, keyTMSISeq).Result()
	if err != nil {
		return 0, fmt.Errorf("amf cache: NextTMSI: %w", err)
	}
	return uint32(v), nil
}

func (c *RedisCache) Close() error {
	return c.client.Close()
}
