# Console Examples

This directory contains example configurations and helper scripts for local development.

## Files

### Bridge Configuration
- **`config.yaml`** - Basic bridge configuration for local development
- **`console-client-secret`** - OAuth client secret
- **`ca.crt`** - Certificate authority for cluster communication
- **`token`** - Authentication token
- **`run-bridge.sh`** - Script to run bridge locally

### Redis Session Testing
- **`start-redis.sh`** - Start Redis in podman for session persistence testing
- **`REDIS_SESSION_CONFIG.md`** - Environment variable configuration documentation

## Quick Start - Local Bridge

```bash
# Run bridge with default configuration
./examples/run-bridge.sh

# Or manually
./bin/bridge \
  --config=examples/config.yaml \
  --public-dir=./frontend/public/dist
```

## Testing Redis Session Persistence

The session store prototype allows testing Redis-backed session persistence locally.

### 1. Start Redis

```bash
./examples/start-redis.sh
```

This script:
- Starts Redis in a podman container
- Waits for Redis to be ready
- Prints the environment variables you need

### 2. Generate Cookie Keys (One-Time Setup)

**Important:** Cookie keys must be persistent across restarts for session persistence to work.

```bash
# Generate 32-byte encryption key (raw binary)
openssl rand 32 > /tmp/cookie-encryption-key

# Generate 64-byte authentication key (raw binary)
openssl rand 64 > /tmp/cookie-authentication-key
```

Keep these files! They must remain the same across bridge restarts.

### 3. Run Bridge with Redis Sessions

```bash
# Enable Redis session store
export BRIDGE_SESSION_STORE_TYPE=redis
export BRIDGE_REDIS_ADDR=localhost:6379

# Run bridge with persistent cookie keys
./bin/bridge \
  --config=examples/config.yaml \
  --public-dir=./frontend/public/dist \
  --cookie-encryption-key-file=/tmp/cookie-encryption-key \
  --cookie-authentication-key-file=/tmp/cookie-authentication-key
```

### 4. Test Session Persistence

1. Login to console at http://localhost:9000
2. Restart bridge (Ctrl+C, then restart with same commands)
3. Refresh browser - you should still be logged in! ✅

The session persisted in Redis across the bridge restart.

### 5. Verify Sessions in Redis

```bash
# Connect to Redis CLI
podman exec -it console-redis redis-cli

# List all sessions
KEYS console:*

# View a session
GET console:session:token:<token>

# Watch operations in real-time
MONITOR
```

## Environment Variables for Session Store

The session store can be configured via environment variables for easy local testing:

- **`BRIDGE_SESSION_STORE_TYPE`** - `redis`, `cached-redis`, or `memory` (default)
- **`BRIDGE_REDIS_ADDR`** - Redis server address (default: `localhost:6379`)
- **`BRIDGE_REDIS_PASSWORD`** - Redis password (optional)
- **`BRIDGE_REDIS_TLS`** - Enable TLS (`true`/`false`)
- **`BRIDGE_REDIS_DB`** - Database number (default: `0`)
- **`BRIDGE_LOCAL_CACHE_SIZE`** - LRU cache size (default: `1000`)

See `REDIS_SESSION_CONFIG.md` for complete documentation and integration examples.

## Managing Redis

```bash
# View Redis logs
podman logs -f console-redis

# Stop Redis
podman stop console-redis

# Restart Redis
podman start console-redis

# Remove Redis (deletes all data)
podman rm -f console-redis

# Check Redis status
podman ps | grep console-redis
```

## Session Store Documentation

For complete documentation on the Redis session store prototype:

- **Architecture & Design:** `../pkg/auth/sessions/PROTOTYPE_README.md`
- **Quick Start Guide:** `../pkg/auth/sessions/WORKING_PROTOTYPE.md`
- **Environment Variables:** `REDIS_SESSION_CONFIG.md`
- **Demo Application:** `go run github.com/openshift/console/pkg/auth/sessions/example`

## Troubleshooting

### Redis won't start
```bash
# Check if port 6379 is in use
lsof -i :6379

# Remove existing container and try again
podman rm -f console-redis
./examples/start-redis.sh
```

### Bridge not connecting to Redis
```bash
# Verify Redis is running
podman exec console-redis redis-cli PING
# Should return: PONG

# Check if environment variables are set
echo $BRIDGE_SESSION_STORE_TYPE
echo $BRIDGE_REDIS_ADDR
```

### Sessions not persisting

**Most common issue:** Cookie keys are not consistent across restarts.

Sessions are stored in Redis, but the session cookies must be decrypted using the same keys. If you're getting logged out on bridge restart:

1. **Check that cookie key files exist and are being used:**
   ```bash
   ls -la /tmp/cookie-*-key
   # Verify bridge is started with --cookie-*-key-file flags
   ```

2. **Verify sessions are in Redis:**
   ```bash
   # Should show session keys
   podman exec -it console-redis redis-cli KEYS console:*
   ```

3. **Watch Redis operations during login:**
   ```bash
   podman exec -it console-redis redis-cli MONITOR
   # Login to console and watch for SET operations
   ```

If you see sessions in Redis but still get logged out, the cookie keys likely changed between restarts.

## More Information

For general OpenShift Console development, see the main README:
```bash
cat ../README.md
```
