package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/maypok86/otter/v2"
)

var (
	ErrCacheNotInitialized = errors.New("cache not initialized")
)

// defaultLoadTimeout bounds a shared load that is detached from any single caller.
const defaultLoadTimeout = 30 * time.Second

type LoaderFunc[V any] func(ctx context.Context) (V, error)

type Cacher[K comparable, V any] interface {
	Get(ctx context.Context, key K, loaderFunc LoaderFunc[V]) (V, error)
	// Clear discards every entry. It is safe for concurrent use and
	// guarantees that loads already in flight cannot repopulate the cache.
	Clear()
}

type call[V any] struct {
	done chan struct{}
	val  V
	err  error
}

type cacher[K comparable, V any] struct {
	cache       *otter.Cache[K, V]
	loadTimeout time.Duration

	mu       sync.Mutex
	inflight map[K]*call[V]
	// gen is bumped by Clear; a load that began before a Clear must not
	// repopulate the cache with possibly stale data.
	gen uint64
}

func NewCacher[K comparable, V any](opts ...Option[K, V]) Cacher[K, V] {

	options := &options[K, V]{
		Capacity: 100,
		Ttl:      1 * time.Hour,
	}
	for _, opt := range opts {
		opt(options)
	}

	return &cacher[K, V]{
		cache: otter.Must(&otter.Options[K, V]{
			MaximumSize:      options.Capacity,
			ExpiryCalculator: otter.ExpiryCreating[K, V](options.Ttl),
		}),
		loadTimeout: defaultLoadTimeout,
		inflight:    make(map[K]*call[V]),
	}
}

// Get returns the cached value or loads it. Concurrent misses for the same
// key share one loader invocation (single-flight). The loader runs detached
// from the first caller's cancellation (bounded by a timeout) so one
// disconnecting client does not fail every waiter; each caller still returns
// as soon as its own ctx is done.
func (c *cacher[K, V]) Get(ctx context.Context, key K, loaderFunc LoaderFunc[V]) (V, error) {
	if c.cache == nil {
		return *new(V), ErrCacheNotInitialized
	}

	if val, found := c.cache.GetIfPresent(key); found {
		return val, nil
	}

	c.mu.Lock()
	// Re-check under the lock: a load may have completed since the first check.
	if val, found := c.cache.GetIfPresent(key); found {
		c.mu.Unlock()
		return val, nil
	}
	cl, ok := c.inflight[key]
	if !ok {
		cl = &call[V]{done: make(chan struct{})}
		c.inflight[key] = cl
		gen := c.gen
		c.mu.Unlock()
		go c.load(ctx, key, cl, gen, loaderFunc)
	} else {
		c.mu.Unlock()
	}

	select {
	case <-cl.done:
		return cl.val, cl.err
	case <-ctx.Done():
		return *new(V), ctx.Err()
	}
}

func (c *cacher[K, V]) load(parent context.Context, key K, cl *call[V], gen uint64, loaderFunc LoaderFunc[V]) {
	defer func() {
		if r := recover(); r != nil {
			cl.val = *new(V)
			cl.err = fmt.Errorf("cache loader panic: %v", r)
		}
		c.mu.Lock()
		if c.inflight[key] == cl {
			delete(c.inflight, key)
		}
		if cl.err == nil && c.gen == gen {
			c.cache.Set(key, cl.val)
		}
		c.mu.Unlock()
		close(cl.done)
	}()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), c.loadTimeout)
	defer cancel()
	cl.val, cl.err = loaderFunc(ctx)
	if cl.err != nil {
		cl.val = *new(V)
	}
}

// Clear discards all entries.
func (c *cacher[K, V]) Clear() {
	if c.cache == nil {
		return
	}
	c.mu.Lock()
	c.gen++
	// Detach in-flight loads so callers arriving after the Clear start a
	// fresh load instead of joining one that began before the write.
	c.inflight = make(map[K]*call[V])
	c.cache.InvalidateAll()
	c.mu.Unlock()
}
