package main

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/console/pkg/auth/sessions"
	"golang.org/x/oauth2"
)

func main() {
	fmt.Println("🚀 OpenShift Console Session Store Prototype Demo")
	fmt.Println("================================================\n")

	ctx := context.Background()

	// Demo 1: Memory Store
	fmt.Println("1. Memory Store (Current Behavior)")
	fmt.Println("   - In-memory session storage")
	fmt.Println("   - Fast but loses sessions on restart")
	memoryStore := sessions.NewServerSessionStore(1000)
	demoStore(ctx, memoryStore, "Memory")

	// Demo 2: Cached Store
	fmt.Println("\n2. Cached Store (Two-Level Cache)")
	fmt.Println("   - Local LRU cache + backend store")
	fmt.Println("   - Best performance with persistence")
	cachedStore := sessions.NewCachedSessionStore(
		sessions.NewServerSessionStore(1000),
		sessions.DefaultSessionStoreConfig(),
	)
	demoStore(ctx, cachedStore, "Cached")

	// Demo 3: Configuration
	fmt.Println("\n3. Configuration Examples")
	printConfigExamples()

	fmt.Println("\n✅ Prototype Demo Complete!")
	fmt.Println("\nNext steps:")
	fmt.Println("  • Add Redis dependency and test RedisSessionStore")
	fmt.Println("  • Run: go get github.com/redis/go-redis/v9")
	fmt.Println("  • See pkg/auth/sessions/PROTOTYPE_README.md for details")
}

func demoStore(ctx context.Context, store sessions.SessionStore, name string) {
	// Create a mock token
	token := &oauth2.Token{
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	// Add a session
	ls, err := store.AddSession(ctx, nil, token)
	if err != nil {
		fmt.Printf("   ❌ Error adding session: %v\n", err)
		return
	}
	fmt.Printf("   ✓ Added session: %s\n", ls.SessionToken()[:16]+"...")

	// Retrieve the session
	retrieved, err := store.GetSession(ctx, ls.SessionToken(), "")
	if err != nil {
		fmt.Printf("   ❌ Error getting session: %v\n", err)
		return
	}
	if retrieved != nil {
		fmt.Printf("   ✓ Retrieved session successfully\n")
	}

	// Health check
	if err := store.HealthCheck(ctx); err != nil {
		fmt.Printf("   ⚠ Health check: %v\n", err)
	} else {
		fmt.Printf("   ✓ Health check passed\n")
	}

	// Delete the session
	if err := store.DeleteSession(ctx, ls.SessionToken()); err != nil {
		fmt.Printf("   ❌ Error deleting session: %v\n", err)
		return
	}
	fmt.Printf("   ✓ Deleted session\n")
}

func printConfigExamples() {
	fmt.Println(`
   Memory (Development):
   --------------------
   session:
     store:
       type: memory
       maxSessions: 1000

   Redis (Production):
   -------------------
   session:
     store:
       type: redis
       redisAddrs:
         - redis-sentinel-1:26379
         - redis-sentinel-2:26379
       redisTLSEnabled: true
       enableFallback: true

   Cached Redis (Recommended):
   ---------------------------
   session:
     store:
       type: cached-redis
       redisAddrs:
         - redis:6379
       enableLocalCache: true
       localCacheSize: 2000
       enableFallback: true
`)
}
