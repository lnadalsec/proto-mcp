package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"
)

// cache stores per-(tool, pid, args) approval entries with an
// absolute expiry. Lookup is two operations — hit() checks + GCs;
// set() writes. Lock is a mutex, not RWMutex, because every read
// path also writes (we sweep expired entries on hit() to keep the
// map bounded).
type cache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key → expires-at (UTC)
	now     func() time.Time     // injectable for tests
	// gen counts purges. A prompt that started before a purge (lock,
	// policy reload) must not repopulate the cache when it returns:
	// the approval was granted under the state the purge revoked.
	gen uint64
}

func newCache() *cache {
	return &cache{
		entries: map[string]time.Time{},
		now:     time.Now,
	}
}

// hit returns true if key has a non-expired entry. Expired entries
// are removed on the way out (lazy GC — saves a separate sweeper
// goroutine).
func (c *cache) hit(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires, ok := c.entries[key]
	if !ok {
		return false
	}
	if c.now().After(expires) {
		delete(c.entries, key)
		return false
	}
	return true
}

// generation returns the current purge count; pass it to setIfGen.
func (c *cache) generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// set stores key with the given TTL from now.
func (c *cache) set(key string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = c.now().Add(ttl)
}

// setIfGen stores key only if no purge happened since gen was read.
// Reports whether the entry was stored.
func (c *cache) setIfGen(key string, ttl time.Duration, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return false
	}
	c.entries[key] = c.now().Add(ttl)
	return true
}

// purge drops every cached approval. SECURITY D14: called after
// `policy reload` (via the broker's Invalidate method) so cached
// approvals issued under the OLD policy don't bypass the NEW
// policy's tightened rules (e.g. confirm:true newly required,
// allowed_recipients newly restricted). Simpler than diff'ing
// every cached key against the new policy — start fresh, the user
// pays at most one re-prompt per tool per TTL window.
func (c *cache) purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = map[string]time.Time{}
	c.gen++
	return n
}

// cacheKey computes sha256(tool || pid || args). PID is included so
// concurrent Claude Desktop sessions (Phase 6 multi-process scenario)
// can't piggyback on each other's approvals. args is included so
// changing the recipient list invalidates a cached approval — the
// safe answer for write tools.
//
// Every variable-length field is length-prefixed (8-byte LE length,
// then bytes) so the encoding is injective: without the prefixes,
// bytes could shift between tool, pid and args and two different
// (tool, pid, args) triples would hash to the same key.
func cacheKey(tool string, pid int, args []byte) string {
	h := sha256.New()
	var buf [8]byte
	writeField := func(b []byte) {
		binary.LittleEndian.PutUint64(buf[:], uint64(len(b)))
		h.Write(buf[:])
		h.Write(b)
	}
	writeField([]byte(tool))
	binary.LittleEndian.PutUint64(buf[:], uint64(pid)) // #nosec G115 -- bit pattern only feeds the hash
	h.Write(buf[:])
	writeField(args)
	return hex.EncodeToString(h.Sum(nil))
}
