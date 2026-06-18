package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "nrf:nf:"

// RedisRegistry implements Registry using Redis.
// NF profiles are stored as JSON strings with TTL = 2 × heartBeatTimer.
// Redis native TTL replaces the eviction goroutine used by InMemory.
// Ref: TS 29.510 §5.2.2.3.4
type RedisRegistry struct {
	client    *redis.Client
	ttl       time.Duration // per-key TTL (2 × heartBeatTimer)
	logger    *slog.Logger
}

// NewRedis connects to Redis and returns a RedisRegistry.
// ttl should be 2 × heartBeatTimer (TS 29.510 §5.2.2.3.4).
func NewRedis(addr string, ttl time.Duration, logger *slog.Logger) (*RedisRegistry, error) {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("nrf redis: ping %s: %w", addr, err)
	}
	return &RedisRegistry{
		client: rdb,
		ttl:    ttl,
		logger: logger.With("component", "registry-redis"),
	}, nil
}

func (r *RedisRegistry) key(id string) string { return keyPrefix + id }

func (r *RedisRegistry) Register(p *NFProfile) error {
	if p.NFInstanceID == "" {
		return fmt.Errorf("nfInstanceId required")
	}
	if p.NFType == "" {
		return fmt.Errorf("nfType required")
	}
	if p.NFStatus == "" {
		p.NFStatus = NFStatusRegistered
	}
	p.HeartBeatTimer = DefaultHeartbeatTimer
	js, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("nrf redis: marshal: %w", err)
	}
	if err := r.client.Set(context.Background(), r.key(p.NFInstanceID), js, r.ttl).Err(); err != nil {
		return fmt.Errorf("nrf redis: SET: %w", err)
	}
	r.logger.Info("NF registered",
		"procedure", "NFRegister",
		"interface", "Nnrf",
		"direction", "IN",
		"target_nf_instance_id", p.NFInstanceID,
		"target_nf_type", p.NFType,
		"spec_ref", "TS 29.510 §5.2.2.2.2",
	)
	return nil
}

func (r *RedisRegistry) Update(id string, p *NFProfile) error {
	p.NFInstanceID = id
	js, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("nrf redis: marshal: %w", err)
	}
	// KEEPTTL preserves the remaining TTL — heartBeatTimer restarts on Heartbeat.
	if err := r.client.Set(context.Background(), r.key(id), js, redis.KeepTTL).Err(); err != nil {
		return fmt.Errorf("nrf redis: SET (update): %w", err)
	}
	r.logger.Info("NF profile updated",
		"procedure", "NFUpdate",
		"interface", "Nnrf",
		"target_nf_instance_id", id,
		"spec_ref", "TS 29.510 §5.2.2.3",
	)
	return nil
}

func (r *RedisRegistry) Deregister(id string) error {
	n, err := r.client.Del(context.Background(), r.key(id)).Result()
	if err != nil {
		return fmt.Errorf("nrf redis: DEL: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("not found: %s", id)
	}
	r.logger.Info("NF deregistered",
		"procedure", "NFDeregister",
		"interface", "Nnrf",
		"target_nf_instance_id", id,
		"spec_ref", "TS 29.510 §5.2.2.4",
	)
	return nil
}

func (r *RedisRegistry) Get(id string) (*NFProfile, bool) {
	js, err := r.client.Get(context.Background(), r.key(id)).Bytes()
	if err != nil {
		return nil, false
	}
	var p NFProfile
	if err := json.Unmarshal(js, &p); err != nil {
		return nil, false
	}
	return &p, true
}

func (r *RedisRegistry) Heartbeat(id string) error {
	ok, err := r.client.Expire(context.Background(), r.key(id), r.ttl).Result()
	if err != nil {
		return fmt.Errorf("nrf redis: EXPIRE: %w", err)
	}
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	return nil
}

// ListAll returns all registered NF profiles from Redis.
// Implements TS 29.510 §5.2.2.6 NFListRetrieval.
func (r *RedisRegistry) ListAll() []*NFProfile {
	return r.Discover(DiscoveryFilter{})
}

// Discover scans all nrf:nf:* keys and filters by the given criteria.
func (r *RedisRegistry) Discover(filter DiscoveryFilter) []*NFProfile {
	ctx := context.Background()
	var keys []string
	iter := r.client.Scan(ctx, 0, keyPrefix+"*", 0).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if iter.Err() != nil {
		r.logger.Error("nrf redis: SCAN failed", "error", iter.Err())
		return nil
	}
	if len(keys) == 0 {
		return nil
	}
	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		r.logger.Error("nrf redis: MGET failed", "error", err)
		return nil
	}
	out := make([]*NFProfile, 0, len(vals))
	for _, v := range vals {
		if v == nil {
			continue
		}
		var p NFProfile
		if err := json.Unmarshal([]byte(v.(string)), &p); err != nil {
			continue
		}
		if filter.TargetNFType != "" && p.NFType != filter.TargetNFType {
			continue
		}
		if !matchServices(p.NFServices, filter.ServiceNames) {
			continue
		}
		if !matchSNSSAIs(p.SNSSAIs, filter.SNSSAIs) {
			continue
		}
		if filter.DNN != "" && !containsDNN(p.DNNList, filter.DNN) {
			continue
		}
		out = append(out, &p)
	}
	r.logger.Info("NF discovery",
		"procedure", "NFDiscover",
		"interface", "Nnrf",
		"target_nf_type", filter.TargetNFType,
		"requester_nf_type", filter.RequesterNFType,
		"results", len(out),
		"spec_ref", "TS 29.510 §5.3.2.2.2",
	)
	return out
}

// Close releases the Redis connection.
func (r *RedisRegistry) Close() error { return r.client.Close() }

// idFromKey strips the keyPrefix from a Redis key.
func idFromKey(k string) string { return strings.TrimPrefix(k, keyPrefix) }
