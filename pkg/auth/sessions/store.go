package sessions

import (
	"context"
	"time"

	"golang.org/x/oauth2"
)

// SessionStore defines the interface for session storage implementations.
// Implementations can be in-memory, Redis-backed, or cached.
type SessionStore interface {
	// AddSession creates a new session from an OAuth2 token.
	// Returns the created LoginState or an error if session creation fails.
	AddSession(ctx context.Context, tokenVerifier IDTokenVerifier, token *oauth2.Token) (*LoginState, error)

	// GetSession retrieves a session by session token or refresh token ID.
	// Returns nil if the session is not found or has expired.
	GetSession(ctx context.Context, sessionToken, refreshTokenID string) (*LoginState, error)

	// UpdateTokens updates the tokens for an existing session.
	// The session is identified by the sessionToken in the LoginState.
	UpdateTokens(ctx context.Context, ls *LoginState, verifier IDTokenVerifier, token *oauth2.Token) error

	// DeleteSession removes a session by session token.
	DeleteSession(ctx context.Context, sessionToken string) error

	// DeleteByRefreshTokenID removes a session by refresh token ID.
	DeleteByRefreshTokenID(ctx context.Context, refreshTokenID string) error

	// GetRefreshToken retrieves the actual refresh token from a refresh token ID.
	// Returns empty string if not found.
	GetRefreshToken(ctx context.Context, refreshTokenID string) (string, error)

	// SetRefreshToken stores a mapping from refresh token ID to actual refresh token.
	SetRefreshToken(ctx context.Context, refreshTokenID, refreshToken string, ttl time.Duration) error

	// Close releases any resources held by the store.
	Close() error

	// HealthCheck returns an error if the store is unhealthy.
	HealthCheck(ctx context.Context) error
}

// SessionStoreConfig holds configuration for session stores.
type SessionStoreConfig struct {
	// Type specifies the session store implementation: "memory", "redis", or "cached-redis"
	Type string

	// Redis configuration
	RedisAddrs      []string // Redis cluster/sentinel addresses
	RedisPassword   string   // Redis password
	RedisTLSEnabled bool     // Enable TLS for Redis connections
	RedisDB         int      // Redis database number
	RedisPoolSize   int      // Connection pool size

	// Cache configuration (for cached-redis type)
	EnableLocalCache bool // Enable local LRU cache
	LocalCacheSize   int  // Number of sessions to cache locally
	CacheTTL         time.Duration

	// Fallback configuration
	EnableFallback bool // Fall back to memory store if Redis is unavailable
	MaxSessions    int  // Maximum sessions for memory store

	// Timeouts
	RedisDialTimeout  time.Duration
	RedisReadTimeout  time.Duration
	RedisWriteTimeout time.Duration
}

// DefaultSessionStoreConfig returns a config with sensible defaults.
func DefaultSessionStoreConfig() *SessionStoreConfig {
	return &SessionStoreConfig{
		Type:              "memory",
		RedisDB:           0,
		RedisPoolSize:     10,
		EnableLocalCache:  true,
		LocalCacheSize:    1000,
		CacheTTL:          5 * time.Minute,
		EnableFallback:    true,
		MaxSessions:       32768,
		RedisDialTimeout:  5 * time.Second,
		RedisReadTimeout:  3 * time.Second,
		RedisWriteTimeout: 3 * time.Second,
	}
}
