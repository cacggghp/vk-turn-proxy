// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// getCredsFunc is the signature for credential retrieval functions
type getCredsFunc func(context.Context, string, int) (string, string, string, error)

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

// StreamCredentialsCache holds credentials cache for a single stream
type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
	streamsPerCache    = 4 // Number of streams sharing one credentials cache
)

// getCacheID returns the shared cache ID for a given stream ID
func getCacheID(streamID int) int {
	return streamID / streamsPerCache
}

// credentialsStore manages per-stream credentials caches
var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

// getStreamCache returns or creates a shared cache for the given stream ID
func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	// Try read lock first for fast path
	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	// Need to create new cache
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

// invalidate invalidates the credentials cache for this stream
func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	// Reset auth error counter
	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	log.Printf("[Auth] Credentials cache invalidated for stream %d", streamID)
}

// fetchMu serializes credential fetching to avoid API rate limiting
var fetchMu sync.Mutex

// fetchFunc is the signature for credential retrieval functions (without cache logic)
type fetchFunc func(ctx context.Context, link string) (string, string, string, error)

// serializeFetch wraps a fetch call with the global fetchMu to avoid API rate limiting
func serializeFetch(ctx context.Context, link string, storeFn fetchFunc) (string, string, string, error) {
	fetchMu.Lock()
	defer fetchMu.Unlock()
	return storeFn(ctx, link)
}

// getCredsCached checks cache before fetching credentials.
// This is the general entry point for credential retrieval with caching.
func getCredsCached(ctx context.Context, link string, streamID int, storeFn fetchFunc) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Check cache - another stream may have populated it while waiting
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		log.Printf("[Auth] Using cached credentials (cache=%d, expires in %v)", cacheID, expires)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}

	log.Printf("[Auth] Cache miss (cache=%d), starting credential fetch...", cacheID)

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	// Fetch credentials with global mutex to avoid API rate limiting
	user, pass, addr, err := serializeFetch(ctx, link, storeFn)

	if err != nil {
		return "", "", "", err
	}

	// Store in cache
	cache.creds = TurnCredentials{
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       link,
	}

	log.Printf("[Auth] Success! Credentials cached until %v (cache=%d)", cache.creds.ExpiresAt, cacheID)
	return user, pass, addr, nil
}
