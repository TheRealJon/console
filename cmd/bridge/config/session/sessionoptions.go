package session

import (
	"flag"
	"fmt"
	"os"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/openshift/console/cmd/bridge/config/flagvalues"
	"github.com/openshift/console/pkg/serverconfig"
)

type SessionOptions struct {
	CookieEncryptionKeyPath     string
	CookieAuthenticationKeyPath string

	// Session store configuration
	SessionStoreType     string
	RedisAddr            string
	RedisPassword        string
	RedisTLS             bool
	RedisDB              int
	LocalCacheSize       int
	EnableFallback       bool
	MaxSessions          int
}

type CompletedOptions struct {
	*completedOptions
}

type completedOptions struct {
	CookieEncryptionKey     []byte
	CookieAuthenticationKey []byte
	SessionStoreConfig      *serverconfig.SessionStoreConfig
}

func NewSessionOptions() *SessionOptions {
	return &SessionOptions{
		CookieEncryptionKeyPath:     "",
		CookieAuthenticationKeyPath: "",

		// Session store defaults
		SessionStoreType: "memory",
		RedisAddr:        "localhost:6379",
		RedisPassword:    "",
		RedisTLS:         false,
		RedisDB:          0,
		LocalCacheSize:   1000,
		EnableFallback:   true,
		MaxSessions:      32768,
	}
}

func (opts *SessionOptions) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&opts.CookieEncryptionKeyPath, "cookie-encryption-key-file", "", "Encryption key used to encrypt cookies. Must be set when --user-auth is 'oidc'.")
	fs.StringVar(&opts.CookieAuthenticationKeyPath, "cookie-authentication-key-file", "", "Authentication key used to sign cookies. Must be set when --user-auth is 'oidc'.")

	// Session store flags
	fs.StringVar(&opts.SessionStoreType, "session-store-type", opts.SessionStoreType, "Session store type: memory, redis, or cached-redis")
	fs.StringVar(&opts.RedisAddr, "redis-addr", opts.RedisAddr, "Redis server address (host:port)")
	fs.StringVar(&opts.RedisPassword, "redis-password", opts.RedisPassword, "Redis authentication password")
	fs.BoolVar(&opts.RedisTLS, "redis-tls", opts.RedisTLS, "Enable TLS for Redis connections")
	fs.IntVar(&opts.RedisDB, "redis-db", opts.RedisDB, "Redis database number")
	fs.IntVar(&opts.LocalCacheSize, "local-cache-size", opts.LocalCacheSize, "Local LRU cache size (for cached-redis type)")
	fs.BoolVar(&opts.EnableFallback, "session-store-fallback", opts.EnableFallback, "Enable fallback to memory store if Redis unavailable")
	fs.IntVar(&opts.MaxSessions, "max-sessions", opts.MaxSessions, "Maximum sessions for memory store")
}

func (opts *SessionOptions) ApplyConfig(config *serverconfig.Session) {
	serverconfig.SetIfUnset(&opts.CookieEncryptionKeyPath, config.CookieEncryptionKeyFile)
	serverconfig.SetIfUnset(&opts.CookieAuthenticationKeyPath, config.CookieAuthenticationKeyFile)

	// Apply session store configuration from config file
	serverconfig.SetIfUnset(&opts.SessionStoreType, config.Store.Type)
	if len(config.Store.RedisAddrs) > 0 {
		serverconfig.SetIfUnset(&opts.RedisAddr, config.Store.RedisAddrs[0])
	}
	serverconfig.SetIfUnset(&opts.RedisPassword, config.Store.RedisPassword)
	if config.Store.RedisTLSEnabled {
		opts.RedisTLS = config.Store.RedisTLSEnabled
	}
	if config.Store.RedisDB != 0 {
		opts.RedisDB = config.Store.RedisDB
	}
	if config.Store.LocalCacheSize != 0 {
		opts.LocalCacheSize = config.Store.LocalCacheSize
	}
	if config.Store.EnableFallback {
		opts.EnableFallback = config.Store.EnableFallback
	}
	if config.Store.MaxSessions != 0 {
		opts.MaxSessions = config.Store.MaxSessions
	}
}

func (opts *SessionOptions) Validate(userAuthType flagvalues.AuthType) []error {
	var errs []error

	// Validate session store type
	switch opts.SessionStoreType {
	case "memory", "redis", "cached-redis":
		// Valid types
	default:
		errs = append(errs, fmt.Errorf("session-store-type must be one of: memory, redis, cached-redis"))
	}

	// Validate Redis configuration when Redis is enabled
	if opts.SessionStoreType == "redis" || opts.SessionStoreType == "cached-redis" {
		if opts.RedisAddr == "" {
			errs = append(errs, fmt.Errorf("redis-addr must be set when session-store-type is %s", opts.SessionStoreType))
		}
	}

	// Cookie keys are required for OIDC always, and for persistent session stores
	// (because keys must be consistent across restarts to decrypt cookies)
	requireCookieKeys := userAuthType == flagvalues.AuthTypeOIDC ||
		opts.SessionStoreType == "redis" ||
		opts.SessionStoreType == "cached-redis"

	if requireCookieKeys {
		if opts.CookieEncryptionKeyPath == "" || opts.CookieAuthenticationKeyPath == "" {
			if userAuthType == flagvalues.AuthTypeOIDC {
				errs = append(errs, fmt.Errorf("cookie-encryption-key-file and cookie-authentication-key-file must be set when --user-auth is 'oidc'"))
			} else {
				errs = append(errs, fmt.Errorf("cookie-encryption-key-file and cookie-authentication-key-file must be set when using persistent session store (redis/cached-redis) to ensure cookies can be decrypted across restarts"))
			}
		}
	}

	return errs
}

func (opts *SessionOptions) Complete(userAuthType flagvalues.AuthType) (*CompletedOptions, error) {
	if errs := opts.Validate(userAuthType); len(errs) > 0 {
		return nil, utilerrors.NewAggregate(errs)
	}

	completed := &completedOptions{}

	if len(opts.CookieEncryptionKeyPath) > 0 {
		encKey, err := os.ReadFile(opts.CookieEncryptionKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open cookie encryption key file %q: %w", opts.CookieEncryptionKeyPath, err)
		}
		completed.CookieEncryptionKey = encKey
	}

	if len(opts.CookieAuthenticationKeyPath) > 0 {
		authnKey, err := os.ReadFile(opts.CookieAuthenticationKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open cookie authentication key file %q: %w", opts.CookieAuthenticationKeyPath, err)
		}
		completed.CookieAuthenticationKey = authnKey
	}

	// Build session store configuration
	completed.SessionStoreConfig = &serverconfig.SessionStoreConfig{
		Type:             opts.SessionStoreType,
		RedisAddrs:       []string{opts.RedisAddr},
		RedisPassword:    opts.RedisPassword,
		RedisTLSEnabled:  opts.RedisTLS,
		RedisDB:          opts.RedisDB,
		RedisPoolSize:    10, // Default pool size
		EnableLocalCache: opts.SessionStoreType == "cached-redis",
		LocalCacheSize:   opts.LocalCacheSize,
		EnableFallback:   opts.EnableFallback,
		MaxSessions:      opts.MaxSessions,
	}

	return &CompletedOptions{
		completedOptions: completed,
	}, nil
}
