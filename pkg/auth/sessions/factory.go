package sessions

import (
	"context"
	"fmt"

	"github.com/openshift/console/pkg/serverconfig"
)

// NewSessionStoreFromConfig creates a SessionStore based on the provided configuration.
// This factory function is the integration point for switching between different store implementations.
func NewSessionStoreFromConfig(ctx context.Context, cfg *serverconfig.SessionStoreConfig) (SessionStore, error) {
	if cfg == nil {
		// Default to in-memory store
		return NewServerSessionStore(32768), nil
	}

	switch cfg.Type {
	case "redis":
		// Pure Redis store with fallback
		storeConfig := &SessionStoreConfig{
			Type:              cfg.Type,
			RedisAddrs:        cfg.RedisAddrs,
			RedisPassword:     cfg.RedisPassword,
			RedisTLSEnabled:   cfg.RedisTLSEnabled,
			RedisDB:           cfg.RedisDB,
			RedisPoolSize:     cfg.RedisPoolSize,
			EnableFallback:    cfg.EnableFallback,
			MaxSessions:       cfg.MaxSessions,
			RedisDialTimeout:  DefaultSessionStoreConfig().RedisDialTimeout,
			RedisReadTimeout:  DefaultSessionStoreConfig().RedisReadTimeout,
			RedisWriteTimeout: DefaultSessionStoreConfig().RedisWriteTimeout,
		}
		return NewRedisSessionStore(ctx, storeConfig)

	case "cached-redis":
		// Redis with local LRU cache
		storeConfig := &SessionStoreConfig{
			Type:              cfg.Type,
			RedisAddrs:        cfg.RedisAddrs,
			RedisPassword:     cfg.RedisPassword,
			RedisTLSEnabled:   cfg.RedisTLSEnabled,
			RedisDB:           cfg.RedisDB,
			RedisPoolSize:     cfg.RedisPoolSize,
			EnableLocalCache:  cfg.EnableLocalCache,
			LocalCacheSize:    cfg.LocalCacheSize,
			EnableFallback:    cfg.EnableFallback,
			MaxSessions:       cfg.MaxSessions,
			RedisDialTimeout:  DefaultSessionStoreConfig().RedisDialTimeout,
			RedisReadTimeout:  DefaultSessionStoreConfig().RedisReadTimeout,
			RedisWriteTimeout: DefaultSessionStoreConfig().RedisWriteTimeout,
		}

		backend, err := NewRedisSessionStore(ctx, storeConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redis backend: %w", err)
		}
		return NewCachedSessionStore(backend, storeConfig), nil

	case "memory", "":
		// In-memory store (current behavior)
		maxSessions := cfg.MaxSessions
		if maxSessions == 0 {
			maxSessions = 32768
		}
		return NewServerSessionStore(maxSessions), nil

	default:
		return nil, fmt.Errorf("unknown session store type: %s", cfg.Type)
	}
}
