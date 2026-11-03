package cache

import "time"

type options[K comparable, V any] struct {
	Capacity int
	Ttl      time.Duration
}

type Option[K comparable, V any] func(*options[K, V])

// WithTTL sets how long an entry lives after creation.
func WithTTL[K comparable, V any](ttl time.Duration) Option[K, V] {
	return func(o *options[K, V]) { o.Ttl = ttl }
}

// WithCapacity sets the maximum number of entries.
func WithCapacity[K comparable, V any](capacity int) Option[K, V] {
	return func(o *options[K, V]) { o.Capacity = capacity }
}
