package sessions

// PROTOTYPE: This file requires the Redis client dependency.
// To add it, run: go get github.com/redis/go-redis/v9

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

const (
	// Redis key prefixes
	keyPrefixSession      = "console:session:token:"
	keyPrefixRefreshToken = "console:session:refresh:"
	keyPrefixRefreshID    = "console:session:refresh-id:"

	// Default TTL for refresh token ID mappings (short-lived)
	defaultRefreshIDTTL = 10 * time.Second
)

// RedisSessionStore implements SessionStore using Redis as the backing store.
type RedisSessionStore struct {
	client      redis.UniversalClient
	config      *SessionStoreConfig
	fallback    *MemorySessionStore
	useFallback bool
}

// NewRedisSessionStore creates a new Redis-backed session store.
func NewRedisSessionStore(ctx context.Context, config *SessionStoreConfig) (*RedisSessionStore, error) {
	if config == nil {
		config = DefaultSessionStoreConfig()
	}

	// Create Redis client
	client := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:        config.RedisAddrs,
		Password:     config.RedisPassword,
		DB:           config.RedisDB,
		PoolSize:     config.RedisPoolSize,
		DialTimeout:  config.RedisDialTimeout,
		ReadTimeout:  config.RedisReadTimeout,
		WriteTimeout: config.RedisWriteTimeout,
	})

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		if config.EnableFallback {
			klog.Warningf("Redis connection failed, falling back to in-memory store: %v", err)
			return &RedisSessionStore{
				client:      client,
				config:      config,
				fallback:    NewServerSessionStore(config.MaxSessions),
				useFallback: true,
			}, nil
		}
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	klog.V(4).Infof("Successfully connected to Redis session store")
	return &RedisSessionStore{
		client:      client,
		config:      config,
		useFallback: false,
	}, nil
}

// AddSession creates a new session from an OAuth2 token.
func (r *RedisSessionStore) AddSession(ctx context.Context, tokenVerifier IDTokenVerifier, token *oauth2.Token) (*LoginState, error) {
	if r.useFallback {
		return r.fallback.AddSession(ctx, tokenVerifier, token)
	}

	// Create login state
	ls, err := newLoginState(tokenVerifier, token)
	if err != nil {
		return nil, fmt.Errorf("failed to create login state: %w", err)
	}

	// Marshal to JSON
	data, err := MarshalLoginState(ls)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login state: %w", err)
	}

	// Calculate TTL from token expiry
	ttl := time.Until(ls.exp)
	if ttl <= 0 {
		return nil, fmt.Errorf("token is already expired")
	}

	// Store session in Redis
	sessionKey := keyPrefixSession + ls.sessionToken
	if err := r.client.Set(ctx, sessionKey, data, ttl).Err(); err != nil {
		if r.config.EnableFallback {
			klog.Warningf("Redis SET failed, falling back to memory: %v", err)
			r.useFallback = true
			if r.fallback == nil {
				r.fallback = NewServerSessionStore(r.config.MaxSessions)
			}
			return r.fallback.AddSession(ctx, tokenVerifier, token)
		}
		return nil, fmt.Errorf("failed to store session in Redis: %w", err)
	}

	// Store refresh token ID mapping (if present)
	if ls.refreshTokenID != "" && ls.refreshToken != "" {
		if err := r.SetRefreshToken(ctx, ls.refreshTokenID, ls.refreshToken, ttl); err != nil {
			klog.Warningf("Failed to store refresh token mapping: %v", err)
		}
	}

	return ls, nil
}

// GetSession retrieves a session by session token or refresh token ID.
func (r *RedisSessionStore) GetSession(ctx context.Context, sessionToken, refreshTokenID string) (*LoginState, error) {
	if r.useFallback {
		return r.fallback.GetSession(ctx, sessionToken, refreshTokenID)
	}

	// Try session token first
	if sessionToken != "" {
		sessionKey := keyPrefixSession + sessionToken
		data, err := r.client.Get(ctx, sessionKey).Bytes()
		if err == nil {
			ls, err := UnmarshalLoginState(data)
			if err != nil {
				klog.Warningf("Failed to unmarshal session: %v", err)
			} else if !ls.IsExpired() {
				return ls, nil
			}
		} else if err != redis.Nil {
			klog.Warningf("Redis GET failed: %v", err)
		}
	}

	// Try refresh token ID
	if refreshTokenID != "" {
		refreshToken, err := r.GetRefreshToken(ctx, refreshTokenID)
		if err == nil && refreshToken != "" {
			// Look up session by refresh token
			// Note: This requires maintaining a reverse index (refreshToken -> sessionToken)
			// For the prototype, we'll skip this optimization and return nil
			klog.V(4).Infof("Refresh token lookup not yet implemented in Redis store")
		}
	}

	return nil, nil
}

// UpdateTokens updates the tokens for an existing session.
func (r *RedisSessionStore) UpdateTokens(ctx context.Context, ls *LoginState, verifier IDTokenVerifier, token *oauth2.Token) error {
	if r.useFallback {
		return ls.UpdateTokens(verifier, token)
	}

	// Update the LoginState
	if err := ls.UpdateTokens(verifier, token); err != nil {
		return err
	}

	// Marshal updated state
	data, err := MarshalLoginState(ls)
	if err != nil {
		return fmt.Errorf("failed to marshal login state: %w", err)
	}

	// Calculate new TTL
	ttl := time.Until(ls.exp)
	if ttl <= 0 {
		return fmt.Errorf("updated token is already expired")
	}

	// Update in Redis
	sessionKey := keyPrefixSession + ls.sessionToken
	if err := r.client.Set(ctx, sessionKey, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to update session in Redis: %w", err)
	}

	// Update refresh token ID mapping if changed
	if ls.refreshTokenID != "" && ls.refreshToken != "" {
		if err := r.SetRefreshToken(ctx, ls.refreshTokenID, ls.refreshToken, ttl); err != nil {
			klog.Warningf("Failed to update refresh token mapping: %v", err)
		}
	}

	return nil
}

// DeleteSession removes a session by session token.
func (r *RedisSessionStore) DeleteSession(ctx context.Context, sessionToken string) error {
	if r.useFallback {
		return r.fallback.DeleteSession(ctx, sessionToken)
	}

	if sessionToken == "" {
		return nil
	}

	sessionKey := keyPrefixSession + sessionToken
	if err := r.client.Del(ctx, sessionKey).Err(); err != nil {
		klog.Warningf("Failed to delete session from Redis: %v", err)
		return err
	}

	return nil
}

// DeleteByRefreshTokenID removes a session by refresh token ID.
func (r *RedisSessionStore) DeleteByRefreshTokenID(ctx context.Context, refreshTokenID string) error {
	if r.useFallback {
		// Memory store doesn't have this method directly
		// This is a limitation we'll handle in the combined store
		return nil
	}

	if refreshTokenID == "" {
		return nil
	}

	// Delete the refresh token ID mapping
	idKey := keyPrefixRefreshID + refreshTokenID
	if err := r.client.Del(ctx, idKey).Err(); err != nil {
		klog.Warningf("Failed to delete refresh token ID mapping: %v", err)
	}

	return nil
}

// GetRefreshToken retrieves the actual refresh token from a refresh token ID.
func (r *RedisSessionStore) GetRefreshToken(ctx context.Context, refreshTokenID string) (string, error) {
	if r.useFallback {
		// Memory fallback stores refresh tokens differently
		return "", nil
	}

	if refreshTokenID == "" {
		return "", nil
	}

	idKey := keyPrefixRefreshID + refreshTokenID
	refreshToken, err := r.client.Get(ctx, idKey).Result()
	if err == redis.Nil {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}

	return refreshToken, nil
}

// SetRefreshToken stores a mapping from refresh token ID to actual refresh token.
func (r *RedisSessionStore) SetRefreshToken(ctx context.Context, refreshTokenID, refreshToken string, ttl time.Duration) error {
	if r.useFallback {
		// Memory fallback handles this differently
		return nil
	}

	if refreshTokenID == "" || refreshToken == "" {
		return nil
	}

	idKey := keyPrefixRefreshID + refreshTokenID
	if err := r.client.Set(ctx, idKey, refreshToken, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set refresh token: %w", err)
	}

	return nil
}

// Close releases any resources held by the store.
func (r *RedisSessionStore) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// HealthCheck returns an error if the store is unhealthy.
func (r *RedisSessionStore) HealthCheck(ctx context.Context) error {
	if r.useFallback {
		return fmt.Errorf("using fallback memory store (Redis unavailable)")
	}

	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis health check failed: %w", err)
	}

	return nil
}
