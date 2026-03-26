# Redis Session Store Configuration

This document describes how to configure the OpenShift Console bridge to use Redis for session persistence via environment variables. This is the recommended approach for local development and testing.

## Important: Cookie Keys Required for Persistent Sessions

When using Redis session persistence (`redis` or `cached-redis`), you **must** provide cookie encryption and authentication keys via files. These keys are used to encrypt session cookies, and they must remain consistent across bridge restarts to decrypt existing cookies.

Without persistent cookie keys, users will be logged out on every bridge restart even though sessions are stored in Redis.

**Required flags:**
- `--cookie-encryption-key-file` (or `BRIDGE_COOKIE_ENCRYPTION_KEY_FILE`)
- `--cookie-authentication-key-file` (or `BRIDGE_COOKIE_AUTHENTICATION_KEY_FILE`)

**Generate keys:**
```bash
# Generate 32-byte encryption key (raw binary)
openssl rand 32 > /tmp/cookie-encryption-key

# Generate 64-byte authentication key (raw binary)
openssl rand 64 > /tmp/cookie-authentication-key
```

## Environment Variables

Bridge automatically reads environment variables with the `BRIDGE_` prefix. Flag names are converted by replacing dashes with underscores and uppercasing.

### `BRIDGE_SESSION_STORE_TYPE`
- **CLI Flag:** `--session-store-type`
- **Type:** `redis` | `cached-redis` | `memory`
- **Default:** `memory`
- **Description:** Session store backend to use

### `BRIDGE_REDIS_ADDR`
- **CLI Flag:** `--redis-addr`
- **Type:** string
- **Default:** `localhost:6379`
- **Description:** Redis server address (host:port)
- **Example:** `redis-sentinel:26379`

### `BRIDGE_REDIS_PASSWORD`
- **CLI Flag:** `--redis-password`
- **Type:** string
- **Default:** "" (no password)
- **Description:** Redis authentication password

### `BRIDGE_REDIS_TLS`
- **CLI Flag:** `--redis-tls`
- **Type:** bool
- **Default:** `false`
- **Description:** Enable TLS for Redis connections

### `BRIDGE_REDIS_DB`
- **CLI Flag:** `--redis-db`
- **Type:** int
- **Default:** `0`
- **Description:** Redis database number

### `BRIDGE_LOCAL_CACHE_SIZE`
- **CLI Flag:** `--local-cache-size`
- **Type:** int
- **Default:** `1000`
- **Description:** Local LRU cache size (for cached-redis type)

### `BRIDGE_SESSION_STORE_FALLBACK`
- **CLI Flag:** `--session-store-fallback`
- **Type:** bool
- **Default:** `true`
- **Description:** Enable fallback to memory store if Redis unavailable

### `BRIDGE_MAX_SESSIONS`
- **CLI Flag:** `--max-sessions`
- **Type:** int
- **Default:** `32768`
- **Description:** Maximum sessions for memory store

## Integration Example

This is how bridge would read these environment variables in `pkg/server/server.go`:

```go
import (
    "os"
    "strconv"
    "github.com/openshift/console/pkg/auth/sessions"
    "github.com/openshift/console/pkg/serverconfig"
)

func getSessionStoreConfig() *serverconfig.SessionStoreConfig {
    config := serverconfig.DefaultSessionStoreConfig()

    // Read from environment variables if set
    if storeType := os.Getenv("BRIDGE_SESSION_STORE_TYPE"); storeType != "" {
        config.Type = storeType
    }

    if redisAddr := os.Getenv("BRIDGE_REDIS_ADDR"); redisAddr != "" {
        config.RedisAddrs = []string{redisAddr}
    }

    if redisPassword := os.Getenv("BRIDGE_REDIS_PASSWORD"); redisPassword != "" {
        config.RedisPassword = redisPassword
    }

    if redisTLS := os.Getenv("BRIDGE_REDIS_TLS"); redisTLS == "true" {
        config.RedisTLSEnabled = true
    }

    if redisDB := os.Getenv("BRIDGE_REDIS_DB"); redisDB != "" {
        if db, err := strconv.Atoi(redisDB); err == nil {
            config.RedisDB = db
        }
    }

    if cacheSize := os.Getenv("BRIDGE_LOCAL_CACHE_SIZE"); cacheSize != "" {
        if size, err := strconv.Atoi(cacheSize); err == nil {
            config.LocalCacheSize = size
        }
    }

    return config
}

// In server initialization:
sessionStoreConfig := getSessionStoreConfig()
sessionStore, err := sessions.NewSessionStoreFromConfig(ctx, sessionStoreConfig)
if err != nil {
    return fmt.Errorf("failed to create session store: %w", err)
}
```

## Usage Examples

### Memory Store (Default)
```bash
# No env vars needed - this is the default
./bin/bridge --your-usual-flags
```

### Redis Store (Local Development)
```bash
# Generate cookie keys (one-time setup)
openssl rand 32 > /tmp/cookie-encryption-key
openssl rand 64 > /tmp/cookie-authentication-key

# Run bridge with Redis sessions
export BRIDGE_SESSION_STORE_TYPE=redis
export BRIDGE_REDIS_ADDR=localhost:6379
./bin/bridge \
  --cookie-encryption-key-file=/tmp/cookie-encryption-key \
  --cookie-authentication-key-file=/tmp/cookie-authentication-key \
  --your-usual-flags
```

### Cached Redis Store (Production)
```bash
# Generate cookie keys (store securely, e.g., in Kubernetes secrets)
openssl rand 32 > /path/to/cookie-encryption-key
openssl rand 64 > /path/to/cookie-authentication-key

export BRIDGE_SESSION_STORE_TYPE=cached-redis
export BRIDGE_REDIS_ADDR=redis-sentinel:26379
export BRIDGE_REDIS_PASSWORD=your-secure-password
export BRIDGE_REDIS_TLS=true
export BRIDGE_LOCAL_CACHE_SIZE=2000
./bin/bridge \
  --cookie-encryption-key-file=/path/to/cookie-encryption-key \
  --cookie-authentication-key-file=/path/to/cookie-authentication-key \
  --your-usual-flags
```

### Redis Cluster
```bash
# Generate cookie keys (store securely)
openssl rand 32 > /path/to/cookie-encryption-key
openssl rand 64 > /path/to/cookie-authentication-key

export BRIDGE_SESSION_STORE_TYPE=redis
export BRIDGE_REDIS_ADDR=redis-cluster-0:6379,redis-cluster-1:6379,redis-cluster-2:6379
export BRIDGE_REDIS_TLS=true
export BRIDGE_REDIS_PASSWORD=${REDIS_PASSWORD}
./bin/bridge \
  --cookie-encryption-key-file=/path/to/cookie-encryption-key \
  --cookie-authentication-key-file=/path/to/cookie-authentication-key \
  --your-usual-flags
```

## Priority

Environment variables take precedence over YAML configuration. This allows:
1. YAML config for base settings
2. Environment variables for deployment-specific overrides
3. Easy local development without touching YAML files

## Notes

- Environment variables are optional - if not set, bridge uses YAML config or defaults
- For production, consider using both: YAML for structure, env vars for secrets
- The existing `serverconfig.Config` YAML structure can still be used alongside env vars
- Env vars make it trivial to test Redis locally: just run the script and set 2 variables
