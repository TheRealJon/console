package sessions

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	consoleUtils "github.com/openshift/console/pkg/utils"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const (
	OpenshiftAccessTokenCookieName  = "openshift-session-token"
	openshiftRefreshTokenCookieName = "openshift-refresh-token"
)

var sessionPruningPeriod = 5 * time.Minute

type MemorySessionStore struct {
	byToken map[string]*LoginState
	// TODO: implement delayed pruning (so that all clients with old refresh token can get the session correctly) when two instances are pointing to the same item (key != ls.refreshToken)
	// TODO: maybe only store indexed by the old refresh tokens and have each item have lifespan of ~10s
	byRefreshToken   map[string]*LoginState
	byRefreshTokenID map[string]string // Maps small reference ID -> actual refresh token
	byAge            []*LoginState
	maxSessions      int
	now              nowFunc
	mux              sync.Mutex
}

func NewServerSessionStore(maxSessions int) *MemorySessionStore {
	ss := &MemorySessionStore{
		byToken:          make(map[string]*LoginState),
		byRefreshToken:   make(map[string]*LoginState),
		byRefreshTokenID: make(map[string]string),
		maxSessions:      maxSessions,
		now:              time.Now,
	}

	go wait.Forever(ss.pruneSessions, sessionPruningPeriod)
	return ss
}

// AddSession implements SessionStore interface - creates a new session from an OAuth2 token.
func (ss *MemorySessionStore) AddSession(ctx context.Context, tokenVerifier IDTokenVerifier, token *oauth2.Token) (*LoginState, error) {
	ls, err := newLoginState(tokenVerifier, token)
	if err != nil {
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	sessionToken := ls.sessionToken

	// Generate a small reference ID for the refresh token (stored in cookie instead of full token)
	ls.refreshTokenID = RandomString(32)

	ss.mux.Lock()
	// Check for collision (should never happen with crypto random)
	if ss.byToken[sessionToken] != nil {
		ss.mux.Unlock()
		return nil, fmt.Errorf("session token collision! THIS SHOULD NEVER HAPPEN! Token: %s", sessionToken)
	}

	ss.byToken[sessionToken] = ls
	if ls.refreshToken != "" {
		ss.byRefreshTokenID[ls.refreshTokenID] = ls.refreshToken
	}

	// Assume token expiration is always the same time in the future. Should be close enough for government work.
	ss.byAge = append(ss.byAge, ls)
	ss.mux.Unlock()
	return ls, nil
}

// GetSession implements SessionStore interface - retrieves a session by session token or refresh token ID.
func (ss *MemorySessionStore) GetSession(ctx context.Context, sessionToken, refreshTokenID string) (*LoginState, error) {
	ss.mux.Lock()
	defer ss.mux.Unlock()
	if state, ok := ss.byToken[sessionToken]; ok {
		return state, nil
	}
	// Look up refresh token from ID
	if refreshToken, ok := ss.byRefreshTokenID[refreshTokenID]; ok {
		return ss.byRefreshToken[refreshToken], nil
	}
	return nil, nil
}

// DeleteSession implements SessionStore interface - removes a session by session token.
func (ss *MemorySessionStore) DeleteSession(ctx context.Context, sessionToken string) error {
	ss.mux.Lock()
	defer ss.mux.Unlock()
	return ss.deleteSessionInternal(sessionToken)
}

// deleteSessionInternal removes a session without locking (caller must hold lock)
func (ss *MemorySessionStore) deleteSessionInternal(sessionToken string) error {
	// not found - return fast
	if _, ok := ss.byToken[sessionToken]; !ok {
		return nil
	}

	delete(ss.byToken, sessionToken)
	for i := 0; i < len(ss.byAge); i++ {
		s := ss.byAge[i]
		if s.sessionToken == sessionToken {
			ss.byAge = append(ss.byAge[:i], ss.byAge[i+1:]...)
			return nil
		}
	}
	klog.Errorf("ss.byAge did not contain session %v", sessionToken)
	return fmt.Errorf("ss.byAge did not contain session %v", sessionToken)
}

func (ss *MemorySessionStore) DeleteByRefreshToken(refreshToken string) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	session, ok := ss.byRefreshToken[refreshToken]
	if !ok {
		return
	}

	delete(ss.byRefreshToken, refreshToken)
	delete(ss.byToken, session.sessionToken)
	ss.deleteIDsForRefreshToken(refreshToken)

	ss.byAge = spliceOut(ss.byAge, session)
}

func (ss *MemorySessionStore) DeleteBySessionToken(sessionToken string) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	session, ok := ss.byToken[sessionToken]
	if !ok {
		return
	}

	delete(ss.byToken, sessionToken)
	ss.byAge = spliceOut(ss.byAge, session)

	ss.deleteRefreshTokenIDsForSession(session)
	ss.deleteRefreshTokensForSession(session)
}

// deleteRefreshTokenIDsForSession removes all refresh token IDs that point to the given session.
// There can be multiple old IDs from previous token rotations.
// Note: This method is not thread-safe and assumes the caller holds ss.mux.
func (ss *MemorySessionStore) deleteRefreshTokenIDsForSession(session *LoginState) {
	for refreshTokenID, actualRefreshToken := range ss.byRefreshTokenID {
		if ss.byRefreshToken[actualRefreshToken] == session {
			delete(ss.byRefreshTokenID, refreshTokenID)
		}
	}
}

// deleteRefreshTokensForSession removes all refresh tokens that point to the given session.
// There can be multiple old tokens from previous token rotations.
// Note: This method is not thread-safe and assumes the caller holds ss.mux.
func (ss *MemorySessionStore) deleteRefreshTokensForSession(session *LoginState) {
	for refreshToken, loginState := range ss.byRefreshToken {
		if loginState == session {
			delete(ss.byRefreshToken, refreshToken)
		}
	}
}

// deleteIDsForRefreshToken removes all refresh token IDs that point to the given refresh token.
// There can be multiple old IDs from previous token rotations.
// Note: This method is not thread-safe and assumes the caller holds ss.mux.
func (ss *MemorySessionStore) deleteIDsForRefreshToken(refreshToken string) {
	for refreshTokenID, actualRefreshToken := range ss.byRefreshTokenID {
		if actualRefreshToken == refreshToken {
			delete(ss.byRefreshTokenID, refreshTokenID)
		}
	}
}

func (ss *MemorySessionStore) pruneSessions() {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	if len(ss.byAge) == 0 {
		return
	}

	if !slices.IsSortedFunc(ss.byAge, loginStateSorter) {
		// sort the byAge slice by current expiry (expiry can change via token refreshes)
		slices.SortFunc(ss.byAge, loginStateSorter)
	}

	// binary search for the first expired session
	firstExpired := sort.Search(len(ss.byAge), func(i int) bool {
		return ss.byAge[i].IsExpired()
	})

	removalPivot := ss.maxSessions
	// if we've got more expired sessions than we need to remove, just remove all expired
	if firstExpired != len(ss.byAge) && firstExpired < removalPivot {
		removalPivot = firstExpired
	}

	if removalPivot < len(ss.byAge) {
		// TODO: account for user ids when pruning old sessions. Otherwise one user could log in 16k times and boot out everyone else.
		for _, s := range ss.byAge[removalPivot:] {
			delete(ss.byToken, s.sessionToken)
			ss.deleteRefreshTokenIDsForSession(s)
			ss.deleteRefreshTokensForSession(s)
		}
		ss.byAge = ss.byAge[:removalPivot]

		klog.V(4).Infof("Pruned %v old sessions.", len(ss.byAge)-removalPivot)
	}
}

func loginStateSorter(a, b *LoginState) int { return a.CompareExpiry(b) }

func RandomString(length int) string {
	str, err := consoleUtils.RandomString(length)
	if err != nil {
		panic(fmt.Sprintf("FATAL ERROR: Unable to get random bytes for session token: %v", err))
	}
	return str
}

func spliceOut(slice []*LoginState, toRemove *LoginState) []*LoginState {
	for i := 0; i < len(slice); i++ {
		s := slice[i]
		// compare pointers, these should be the same in the byAge cache
		if s == toRemove {
			// splice out the session from the slice
			return append(slice[:i], slice[i+1:]...)

		}
	}
	return slice
}

// UpdateTokens implements SessionStore interface - updates the tokens for an existing session.
func (ss *MemorySessionStore) UpdateTokens(ctx context.Context, ls *LoginState, verifier IDTokenVerifier, token *oauth2.Token) error {
	return ls.UpdateTokens(verifier, token)
}

// DeleteByRefreshTokenID implements SessionStore interface - removes a session by refresh token ID.
func (ss *MemorySessionStore) DeleteByRefreshTokenID(ctx context.Context, refreshTokenID string) error {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	// Look up the actual refresh token from the ID
	refreshToken, ok := ss.byRefreshTokenID[refreshTokenID]
	if !ok {
		return nil
	}

	// Delete the session by refresh token
	session, ok := ss.byRefreshToken[refreshToken]
	if !ok {
		return nil
	}

	delete(ss.byRefreshToken, refreshToken)
	delete(ss.byToken, session.sessionToken)
	delete(ss.byRefreshTokenID, refreshTokenID)
	ss.byAge = spliceOut(ss.byAge, session)

	return nil
}

// GetRefreshToken implements SessionStore interface - retrieves the actual refresh token from a refresh token ID.
func (ss *MemorySessionStore) GetRefreshToken(ctx context.Context, refreshTokenID string) (string, error) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	if refreshToken, ok := ss.byRefreshTokenID[refreshTokenID]; ok {
		return refreshToken, nil
	}
	return "", nil
}

// SetRefreshToken implements SessionStore interface - stores a mapping from refresh token ID to actual refresh token.
func (ss *MemorySessionStore) SetRefreshToken(ctx context.Context, refreshTokenID, refreshToken string, ttl time.Duration) error {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	ss.byRefreshTokenID[refreshTokenID] = refreshToken
	return nil
}

// Close implements SessionStore interface - releases any resources held by the store.
func (ss *MemorySessionStore) Close() error {
	// Memory store has no resources to release
	return nil
}

// HealthCheck implements SessionStore interface - returns an error if the store is unhealthy.
func (ss *MemorySessionStore) HealthCheck(ctx context.Context) error {
	// Memory store is always healthy
	return nil
}
