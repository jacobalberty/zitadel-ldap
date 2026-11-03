package cache

import (
	"context"
	"errors"
	"time"

	"github.com/maypok86/otter/v2"
)

var (
	ErrCacheNotInitialized = errors.New("cache not initialized")
)

type LoaderFunc[V any] func(ctx context.Context) (V, error)

type Cacher[K comparable, V any] interface {
	Get(ctx context.Context, key K, loaderFunc LoaderFunc[V]) (V, error)
	GetMany(ctx context.Context, keys []K, loaderFunc LoaderFunc[map[K]V]) (map[K]V, error)
	// Clear discards every entry. It is safe for concurrent use.
	Clear()
}

type cacher[K comparable, V any] struct {
	cache *otter.Cache[K, V]
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
	}
}

func (c *cacher[K, V]) Get(ctx context.Context, key K, loaderFunc LoaderFunc[V]) (V, error) {
	if c.cache == nil {
		return *new(V), ErrCacheNotInitialized
	}

	if val, found := c.cache.GetIfPresent(key); found {
		return val, nil
	}

	val, err := loaderFunc(ctx)
	if err != nil {
		return *new(V), err
	}

	c.cache.Set(key, val)

	return val, nil
}

func (c *cacher[K, V]) GetMany(ctx context.Context, keys []K, loaderFunc LoaderFunc[map[K]V]) (map[K]V, error) {
	if c.cache == nil {
		return nil, ErrCacheNotInitialized
	}

	result := make(map[K]V)
	var keysToLoad []K
	for _, key := range keys {
		if val, found := c.cache.GetIfPresent(key); found {
			result[key] = val
		} else {
			keysToLoad = append(keysToLoad, key)
		}
	}

	if len(keysToLoad) == 0 {
		return result, nil
	}

	loadedValues, err := loaderFunc(ctx)
	if err != nil {
		return nil, err
	}

	for key, val := range loadedValues {
		c.cache.Set(key, val)
		result[key] = val
	}

	return result, nil
}

// Clear discards all entries.
func (c *cacher[K, V]) Clear() {
	if c.cache != nil {
		c.cache.InvalidateAll()
	}
}
