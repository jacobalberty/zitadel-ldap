package cache

import "time"

type options[K comparable, V any] struct {
	Capacity int
	Ttl      time.Duration
}

type Option[K comparable, V any] func(*options[K, V])
