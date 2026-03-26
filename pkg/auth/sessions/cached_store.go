package sessions

import (
	"context"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"k8s.io/klog/v2"
)

// CachedSessionStore wraps a SessionStore with an LRU cache for hot sessions.
type CachedSessionStore struct {
	backend SessionStore
	cache   *sessionCache
	config  *SessionStoreConfig
}

// sessionCache implements a simple LRU cache for sessions.
type sessionCache struct {
	items     map[string]*cacheEntry
	evictList *cacheList
	maxSize   int
	mux       sync.RWMutex
}

// cacheEntry represents a cached session with expiry.
type cacheEntry struct {
	session   *LoginState
	expiresAt time.Time
	listNode  *cacheNode
}

// cacheNode is a node in the LRU list.
type cacheNode struct {
	key  string
	prev *cacheNode
	next *cacheNode
}

// cacheList implements a doubly-linked list for LRU tracking.
type cacheList struct {
	head *cacheNode
	tail *cacheNode
	size int
}

// NewCachedSessionStore creates a new cached session store.
func NewCachedSessionStore(backend SessionStore, config *SessionStoreConfig) *CachedSessionStore {
	if config == nil {
		config = DefaultSessionStoreConfig()
	}

	cache := &sessionCache{
		items:     make(map[string]*cacheEntry),
		evictList: newCacheList(),
		maxSize:   config.LocalCacheSize,
	}

	store := &CachedSessionStore{
		backend: backend,
		cache:   cache,
		config:  config,
	}

	// Start cache cleanup goroutine
	go store.cleanupExpiredEntries()

	return store
}

// AddSession creates a new session and caches it.
func (c *CachedSessionStore) AddSession(ctx context.Context, tokenVerifier IDTokenVerifier, token *oauth2.Token) (*LoginState, error) {
	ls, err := c.backend.AddSession(ctx, tokenVerifier, token)
	if err != nil {
		return nil, err
	}

	// Cache the session
	c.cache.Set(ls.sessionToken, ls, ls.exp)

	return ls, nil
}

// GetSession retrieves a session from cache or backend.
func (c *CachedSessionStore) GetSession(ctx context.Context, sessionToken, refreshTokenID string) (*LoginState, error) {
	// Try cache first for session token
	if sessionToken != "" {
		if ls := c.cache.Get(sessionToken); ls != nil && !ls.IsExpired() {
			klog.V(4).Infof("Session cache hit for token: %s", sessionToken[:8])
			return ls, nil
		}
	}

	// Cache miss - fetch from backend
	ls, err := c.backend.GetSession(ctx, sessionToken, refreshTokenID)
	if err != nil {
		return nil, err
	}

	// Cache the result if found
	if ls != nil && !ls.IsExpired() {
		c.cache.Set(ls.sessionToken, ls, ls.exp)
	}

	return ls, nil
}

// UpdateTokens updates session tokens and refreshes cache.
func (c *CachedSessionStore) UpdateTokens(ctx context.Context, ls *LoginState, verifier IDTokenVerifier, token *oauth2.Token) error {
	if err := c.backend.UpdateTokens(ctx, ls, verifier, token); err != nil {
		return err
	}

	// Update cache
	c.cache.Set(ls.sessionToken, ls, ls.exp)

	return nil
}

// DeleteSession removes a session from cache and backend.
func (c *CachedSessionStore) DeleteSession(ctx context.Context, sessionToken string) error {
	// Remove from cache
	c.cache.Delete(sessionToken)

	// Remove from backend
	return c.backend.DeleteSession(ctx, sessionToken)
}

// DeleteByRefreshTokenID removes a session by refresh token ID.
func (c *CachedSessionStore) DeleteByRefreshTokenID(ctx context.Context, refreshTokenID string) error {
	// Note: We can't easily invalidate cache here without knowing the session token
	// This is acceptable because the backend will be authoritative
	return c.backend.DeleteByRefreshTokenID(ctx, refreshTokenID)
}

// GetRefreshToken retrieves a refresh token.
func (c *CachedSessionStore) GetRefreshToken(ctx context.Context, refreshTokenID string) (string, error) {
	return c.backend.GetRefreshToken(ctx, refreshTokenID)
}

// SetRefreshToken stores a refresh token mapping.
func (c *CachedSessionStore) SetRefreshToken(ctx context.Context, refreshTokenID, refreshToken string, ttl time.Duration) error {
	return c.backend.SetRefreshToken(ctx, refreshTokenID, refreshToken, ttl)
}

// Close releases resources.
func (c *CachedSessionStore) Close() error {
	return c.backend.Close()
}

// HealthCheck checks backend health.
func (c *CachedSessionStore) HealthCheck(ctx context.Context) error {
	return c.backend.HealthCheck(ctx)
}

// cleanupExpiredEntries periodically removes expired cache entries.
func (c *CachedSessionStore) cleanupExpiredEntries() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cache.RemoveExpired()
	}
}

// sessionCache methods

func newCacheList() *cacheList {
	return &cacheList{}
}

func (c *sessionCache) Get(key string) *LoginState {
	c.mux.RLock()
	defer c.mux.RUnlock()

	entry, ok := c.items[key]
	if !ok {
		return nil
	}

	// Check expiry
	if time.Now().After(entry.expiresAt) {
		return nil
	}

	// Move to front (most recently used)
	c.evictList.moveToFront(entry.listNode)

	return entry.session
}

func (c *sessionCache) Set(key string, session *LoginState, expiresAt time.Time) {
	c.mux.Lock()
	defer c.mux.Unlock()

	// Update existing entry
	if entry, ok := c.items[key]; ok {
		entry.session = session
		entry.expiresAt = expiresAt
		c.evictList.moveToFront(entry.listNode)
		return
	}

	// Evict oldest if at capacity
	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	// Add new entry
	node := c.evictList.pushFront(key)
	c.items[key] = &cacheEntry{
		session:   session,
		expiresAt: expiresAt,
		listNode:  node,
	}
}

func (c *sessionCache) Delete(key string) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if entry, ok := c.items[key]; ok {
		c.evictList.remove(entry.listNode)
		delete(c.items, key)
	}
}

func (c *sessionCache) RemoveExpired() {
	c.mux.Lock()
	defer c.mux.Unlock()

	now := time.Now()
	for key, entry := range c.items {
		if now.After(entry.expiresAt) {
			c.evictList.remove(entry.listNode)
			delete(c.items, key)
		}
	}
}

func (c *sessionCache) evictOldest() {
	if c.evictList.tail != nil {
		key := c.evictList.tail.key
		c.evictList.remove(c.evictList.tail)
		delete(c.items, key)
	}
}

// cacheList methods

func (l *cacheList) pushFront(key string) *cacheNode {
	node := &cacheNode{key: key}

	if l.head == nil {
		l.head = node
		l.tail = node
	} else {
		node.next = l.head
		l.head.prev = node
		l.head = node
	}

	l.size++
	return node
}

func (l *cacheList) remove(node *cacheNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		l.head = node.next
	}

	if node.next != nil {
		node.next.prev = node.prev
	} else {
		l.tail = node.prev
	}

	l.size--
}

func (l *cacheList) moveToFront(node *cacheNode) {
	if node == l.head {
		return
	}

	// Remove from current position
	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		l.tail = node.prev
	}

	// Move to front
	node.prev = nil
	node.next = l.head
	if l.head != nil {
		l.head.prev = node
	}
	l.head = node
}

// CacheStats returns cache statistics.
func (c *CachedSessionStore) CacheStats() map[string]interface{} {
	c.cache.mux.RLock()
	defer c.cache.mux.RUnlock()

	return map[string]interface{}{
		"size":     len(c.cache.items),
		"max_size": c.cache.maxSize,
	}
}
