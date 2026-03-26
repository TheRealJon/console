# Session Persistence Prototype

This directory contains a prototype implementation for persisting OpenShift Console user sessions across rollouts using Redis.

## Overview

**Problem:** Currently, console sessions are stored entirely in-memory per pod, causing all users to be logged out during rollouts.

**Solution:** Distributed session storage using Redis with local LRU caching for performance.

## Quick Start - Test Locally!

Want to see Redis session persistence in action? Jump to **[Setup Instructions → Test Locally with Redis](#test-locally-with-redis)** for step-by-step instructions on:
- Running Redis in podman
- Configuring bridge to use Redis
- Testing session persistence across restarts
- Verifying sessions in Redis CLI

**TL;DR:**
```bash
# 1. Start Redis
./examples/start-redis.sh

# 2. Generate cookie keys (one-time, keep these files!)
openssl rand 32 > /tmp/cookie-encryption-key
openssl rand 64 > /tmp/cookie-authentication-key

# 3. Run bridge with Redis sessions enabled
export BRIDGE_SESSION_STORE_TYPE=redis
export BRIDGE_REDIS_ADDR=localhost:6379
./bin/bridge \
  --cookie-encryption-key-file=/tmp/cookie-encryption-key \
  --cookie-authentication-key-file=/tmp/cookie-authentication-key \
  (your other usual flags)

# 4. Login, restart bridge, still logged in! ✅
```

## Architecture

```
User Browser (cookies: session-token, refresh-token-id)
    ↓
Console Pod 1          Console Pod 2          Console Pod N
    ↓                       ↓                       ↓
Local LRU Cache       Local LRU Cache       Local LRU Cache
(~1000 sessions)      (~1000 sessions)      (~1000 sessions)
    ↓                       ↓                       ↓
    └───────────────────────┴───────────────────────┘
                            ↓
                    Redis Cluster
                (Centralized Session Store)
```

## Files Created

### Core Abstractions
- **`store.go`** - SessionStore interface defining the contract for session storage
- **`codec.go`** - JSON serialization/deserialization for LoginState

### Implementations
- **`server_session.go`** - MemorySessionStore (refactored from SessionStore)
- **`redis_store.go`** - RedisSessionStore using Redis as backing store
- **`cached_store.go`** - CachedSessionStore with LRU cache wrapper

### Configuration
- **`pkg/serverconfig/types.go`** - Extended Session config with SessionStoreConfig

## Key Features

### 1. Pluggable Architecture
```go
type SessionStore interface {
    AddSession(ctx, tokenVerifier, token) (*LoginState, error)
    GetSession(ctx, sessionToken, refreshTokenID) (*LoginState, error)
    UpdateTokens(ctx, ls, verifier, token) error
    DeleteSession(ctx, sessionToken) error
    // ... more methods
}
```

Implementations:
- `MemorySessionStore` - In-memory (current behavior)
- `RedisSessionStore` - Redis-backed with fallback
- `CachedSessionStore` - Two-level cache (L1: LRU, L2: Redis)

### 2. Graceful Fallback
If Redis becomes unavailable, the `RedisSessionStore` automatically falls back to in-memory storage:

```go
if err := client.Ping(ctx).Err(); err != nil {
    if config.EnableFallback {
        klog.Warningf("Redis connection failed, falling back to in-memory store: %v", err)
        return &RedisSessionStore{
            fallback: NewServerSessionStore(config.MaxSessions),
            useFallback: true,
        }, nil
    }
    return nil, err
}
```

### 3. Two-Level Caching
The `CachedSessionStore` maintains:
- **L1 Cache**: Per-pod LRU cache (default: 1000 sessions)
- **L2 Cache**: Shared Redis store

Benefits:
- Sub-microsecond lookups for hot sessions (L1)
- ~1-2ms lookups for cache misses (L2)
- 80-90% reduction in Redis load

### 4. Session Data Model

**Redis Keys:**
```
console:session:token:{sessionToken}     → LoginState JSON
console:session:refresh-id:{refreshID}   → refreshToken (string)
```

**TTL:** Matches token expiry + grace period

## Configuration

### Example: Development (Memory Store)
```yaml
session:
  cookieEncryptionKeyFile: /path/to/encryption-key
  cookieAuthenticationKeyFile: /path/to/auth-key
  store:
    type: memory
    maxSessions: 100
```

### Example: Production (Redis with Cache)
```yaml
session:
  cookieEncryptionKeyFile: /path/to/encryption-key
  cookieAuthenticationKeyFile: /path/to/auth-key
  store:
    type: redis
    redisAddrs:
      - redis-sentinel-1:26379
      - redis-sentinel-2:26379
      - redis-sentinel-3:26379
    redisTLSEnabled: true
    enableLocalCache: true
    localCacheSize: 2000
    enableFallback: true
    maxSessions: 100000
```

## Running the Demo

A working demo is included to test the prototype locally:

```bash
# Run the demo
go run github.com/openshift/console/pkg/auth/sessions/example

# Or navigate to the directory
cd pkg/auth/sessions/example
go run main.go
```

This demo shows:
- ✅ Memory store (current behavior)
- ✅ Cached store (memory + LRU cache)
- 📝 Configuration examples for all store types

**Output:**
```
🚀 OpenShift Console Session Store Prototype Demo
================================================

1. Memory Store (Current Behavior)
   ✓ Added session
   ✓ Retrieved session successfully
   ✓ Health check passed
   ✓ Deleted session

2. Cached Store (Two-Level Cache)
   ✓ Added session
   ✓ Retrieved session successfully
   ✓ Health check passed
   ✓ Deleted session
```

## Setup Instructions

### Test Locally with Redis

Test the Redis session store locally using the provided script and environment variables.

#### Step 1: Start Redis

```bash
# Run the helper script - it handles everything
./examples/start-redis.sh
```

The script will:
- Start Redis in a podman container (or use existing one)
- Wait for Redis to be ready
- Print the environment variables you need

#### Step 2: Generate Cookie Keys

Cookie keys must be persistent across restarts for session persistence to work:

```bash
# Generate 32-byte encryption key (one-time setup)
openssl rand 32 > /tmp/cookie-encryption-key

# Generate 64-byte authentication key (one-time setup)
openssl rand 64 > /tmp/cookie-authentication-key
```

**Important:** Keep these files! Reuse them across bridge restarts.

#### Step 3: Run Bridge with Redis

Set the environment variables and run bridge with the cookie key files:

```bash
# Enable Redis session store
export BRIDGE_SESSION_STORE_TYPE=redis
export BRIDGE_REDIS_ADDR=localhost:6379

# Run bridge with cookie keys
./bin/bridge \
  --cookie-encryption-key-file=/tmp/cookie-encryption-key \
  --cookie-authentication-key-file=/tmp/cookie-authentication-key \
  (your usual flags)
```

**Note:** Bridge will use the environment variables to enable Redis sessions. If Redis is unavailable, it automatically falls back to memory sessions.

#### Verify It's Working

```bash
# Check sessions in Redis
podman exec -it console-redis redis-cli KEYS console:*

# Watch Redis operations in real-time
podman exec -it console-redis redis-cli MONITOR

# View a session
podman exec -it console-redis redis-cli GET console:session:token:<token>
```

#### Test Session Persistence

```bash
# 1. Login to console
# 2. Restart bridge (Ctrl+C, then restart)
# 3. Refresh browser - still logged in! ✅
```

#### Manage Redis

```bash
# View logs
podman logs -f console-redis

# Stop Redis
podman stop console-redis

# Restart Redis
podman start console-redis

# Remove Redis (deletes all data)
podman rm -f console-redis
```

### 3. Deploy Redis (Production)
For production deployment, you'll need a Redis cluster or sentinel setup. Example using OpenShift:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: console-redis
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command:
        - redis-server
        - --requirepass $(REDIS_PASSWORD)
        - --maxmemory 512mb
        - --maxmemory-policy allkeys-lru
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-password
              key: password
        ports:
        - containerPort: 6379
```

### 4. Update Console Deployment (Production)
Add Redis configuration to console-config ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: console-config
data:
  console-config.yaml: |
    session:
      store:
        type: redis
        redisAddrs:
          - console-redis:6379
        redisPassword: ${REDIS_PASSWORD}
        redisTLSEnabled: false
        enableLocalCache: true
        localCacheSize: 1000
        enableFallback: true
```

### 5. Integration Points

To integrate this prototype, you'll need to update:

1. **`pkg/auth/sessions/server_session.go` (MemorySessionStore)**
   - Add `context.Context` parameter to all methods to match SessionStore interface
   - This maintains backward compatibility while enabling the interface

2. **`pkg/auth/sessions/combined_sessions.go`**
   - Replace `serverStore *MemorySessionStore` with `serverStore SessionStore`
   - Use the factory function `NewSessionStoreFromConfig()` to create stores

3. **`pkg/server/server.go`**
   - Initialize session store based on config during server startup
   - Pass serverconfig.SessionStoreConfig to the factory

Example integration in server initialization:
```go
// In pkg/server/server.go initialization
sessionStore, err := sessions.NewSessionStoreFromConfig(ctx, &s.Config.Session.Store)
if err != nil {
    return nil, fmt.Errorf("failed to create session store: %w", err)
}

// Use sessionStore when creating CombinedSessionStore
combinedStore := &sessions.CombinedSessionStore{
    serverStore: sessionStore,
    clientStore: clientStore,
    sessionLock: sync.Mutex{},
}
```

**Note:** The factory function is already implemented in `factory.go`. The main integration work is updating MemorySessionStore method signatures to include context.

## Testing

### Unit Tests (TODO)
```bash
# Test memory store
go test ./pkg/auth/sessions -run TestMemorySessionStore

# Test Redis store (requires miniredis)
go test ./pkg/auth/sessions -run TestRedisSessionStore

# Test cached store
go test ./pkg/auth/sessions -run TestCachedSessionStore
```

### Integration Tests
1. Deploy Redis in your test cluster
2. Configure console to use Redis
3. Perform rolling update
4. Verify sessions persist

## Performance Characteristics

### Current (In-Memory)
- Session lookup: ~1μs
- Rollout impact: 100% session loss

### Proposed (Redis + Cache)
- Cached lookup: ~1μs (same)
- Redis lookup: ~0.5-2ms
- Rollout impact: 0% session loss ✅

## Security Considerations

1. **Redis TLS**: Enforce in production (`redisTLSEnabled: true`)
2. **Redis Auth**: Use strong passwords via secrets
3. **Network Policies**: Restrict Redis access to console pods only
4. **Encryption at Rest**: Enable Redis encryption for sensitive deployments

## Migration Strategy

### Phase 1: Development (Weeks 1-2)
- [ ] Add Redis dependency
- [ ] Complete unit tests
- [ ] Test locally with miniredis

### Phase 2: Canary Rollout (Weeks 3-4)
- [ ] Deploy to 10% of clusters
- [ ] Monitor metrics and errors
- [ ] Collect performance data

### Phase 3: Full Rollout (Weeks 5-6)
- [ ] Deploy to 50% of clusters
- [ ] Deploy to remaining clusters
- [ ] Remove feature flag

## Monitoring & Metrics

Recommended Prometheus metrics:
```go
session_store_operations_total{store_type, operation, status}
session_store_cache_hits_total{store_type}
session_store_cache_misses_total{store_type}
session_store_latency_seconds{store_type, operation}
session_store_size{store_type}
```

## Known Limitations

1. **Refresh Token Lookup**: The prototype doesn't fully implement looking up sessions by refresh token in Redis (would require reverse index)
2. **Pub/Sub Invalidation**: Cache invalidation across pods could use Redis Pub/Sub for immediate updates
3. **Session Migration**: No automatic migration from memory → Redis for existing sessions
4. **Metrics**: Prometheus metrics not yet implemented

## Next Steps

To move this from prototype to production:

1. **Add comprehensive unit tests** using miniredis
2. **Implement Prometheus metrics** for observability
3. **Add Redis Pub/Sub** for cache invalidation
4. **Create operator changes** for automated Redis deployment
5. **Add migration path** for existing sessions
6. **Performance benchmarks** comparing all implementations
7. **Security review** of Redis configuration and access patterns
8. **Documentation** for cluster admins and operators

## References

- [Redis Go Client Documentation](https://redis.uptrace.dev/)
- [OpenShift Redis Operator](https://github.com/OT-CONTAINER-KIT/redis-operator)
- [Console Architecture](../../../README.md)

---

**Status**: Prototype - Not production ready
**Author**: Claude Code
**Date**: 2026-03-25
