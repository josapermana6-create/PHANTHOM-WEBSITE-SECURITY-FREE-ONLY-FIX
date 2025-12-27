package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/phantom-security/ips-service/internal/models"
)

// RedisStore handles Redis caching operations
type RedisStore struct {
	client  *redis.Client
	enabled bool
}

// NewRedisStore creates a new Redis store
func NewRedisStore(host, password string, db int, enabled bool) (*RedisStore, error) {
	if !enabled {
		return &RedisStore{enabled: false}, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     host,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStore{
		client:  client,
		enabled: true,
	}, nil
}

// GetIPReputation retrieves IP reputation from cache
func (r *RedisStore) GetIPReputation(ctx context.Context, ip string) (*models.IPReputation, error) {
	if !r.enabled {
		return nil, fmt.Errorf("redis disabled")
	}

	key := fmt.Sprintf("ip:reputation:%s", ip)
	data, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil // Not found
	} else if err != nil {
		return nil, err
	}

	var rep models.IPReputation
	if err := json.Unmarshal([]byte(data), &rep); err != nil {
		return nil, err
	}

	return &rep, nil
}

// SetIPReputation caches IP reputation
func (r *RedisStore) SetIPReputation(ctx context.Context, rep *models.IPReputation, ttl time.Duration) error {
	if !r.enabled {
		return nil
	}

	key := fmt.Sprintf("ip:reputation:%s", rep.IPAddress)
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, data, ttl).Err()
}

// IsBlacklisted checks if IP is in blacklist
func (r *RedisStore) IsBlacklisted(ctx context.Context, ip string) (bool, error) {
	if !r.enabled {
		return false, nil
	}

	return r.client.SIsMember(ctx, "ip:blacklist", ip).Result()
}

// IsWhitelisted checks if IP is in whitelist
func (r *RedisStore) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	if !r.enabled {
		return false, nil
	}

	return r.client.SIsMember(ctx, "ip:whitelist", ip).Result()
}

// AddToBlacklist adds IP to blacklist
func (r *RedisStore) AddToBlacklist(ctx context.Context, ip string, duration time.Duration) error {
	if !r.enabled {
		return nil
	}

	if err := r.client.SAdd(ctx, "ip:blacklist", ip).Err(); err != nil {
		return err
	}

	if duration > 0 {
		key := fmt.Sprintf("ip:blacklist:expires:%s", ip)
		return r.client.Set(ctx, key, time.Now().Add(duration).Unix(), duration).Err()
	}

	return nil
}

// AddToWhitelist adds IP to whitelist
func (r *RedisStore) AddToWhitelist(ctx context.Context, ip string) error {
	if !r.enabled {
		return nil
	}

	return r.client.SAdd(ctx, "ip:whitelist", ip).Err()
}

// IncrementRequestCount increments request count for IP
func (r *RedisStore) IncrementRequestCount(ctx context.Context, ip string, window time.Duration) (int64, error) {
	if !r.enabled {
		return 0, nil
	}

	key := fmt.Sprintf("ip:requests:%s", ip)
	pipe := r.client.Pipeline()
	
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}

	return incr.Val(), nil
}

// GetRequestCount gets current request count for IP
func (r *RedisStore) GetRequestCount(ctx context.Context, ip string) (int64, error) {
	if !r.enabled {
		return 0, nil
	}

	key := fmt.Sprintf("ip:requests:%s", ip)
	return r.client.Get(ctx, key).Int64()
}

// IsThreatIntel checks if IP is in threat intelligence cache
func (r *RedisStore) IsThreatIntel(ctx context.Context, ip string) (bool, error) {
	if !r.enabled {
		return false, nil
	}

	return r.client.SIsMember(ctx, "threat:intel", ip).Result()
}

// AddThreatIntel adds IP to threat intelligence cache
func (r *RedisStore) AddThreatIntel(ctx context.Context, ip string, ttl time.Duration) error {
	if !r.enabled {
		return nil
	}

	if err := r.client.SAdd(ctx, "threat:intel", ip).Err(); err != nil {
		return err
	}

	if ttl > 0 {
		key := fmt.Sprintf("threat:intel:expires:%s", ip)
		return r.client.Set(ctx, key, time.Now().Add(ttl).Unix(), ttl).Err()
	}

	return nil
}

// Close closes the Redis connection
func (r *RedisStore) Close() error {
	if r.enabled && r.client != nil {
		return r.client.Close()
	}
	return nil
}
