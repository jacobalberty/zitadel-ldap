package cache

import (
	"context"
	"testing"
	"time"
)

func TestGetCachesValue(t *testing.T) {
	c := NewCacher[string, int]()
	calls := 0

	val, err := c.Get(context.Background(), "k1", func(ctx context.Context) (int, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 42 {
		t.Fatalf("expected 42, got %d", val)
	}

	val, err = c.Get(context.Background(), "k1", func(ctx context.Context) (int, error) {
		calls++
		return 7, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 42 {
		t.Fatalf("expected cached 42, got %d", val)
	}
	if calls != 1 {
		t.Fatalf("expected loader called once, got %d", calls)
	}
}

func TestGetManyLoadsMissingKeys(t *testing.T) {
	c := NewCacher[string, int]()
	_, _ = c.Get(context.Background(), "k1", func(ctx context.Context) (int, error) {
		return 1, nil
	})

	calls := 0
	vals, err := c.GetMany(context.Background(), []string{"k1", "k2"}, func(ctx context.Context) (map[string]int, error) {
		calls++
		return map[string]int{"k2": 2}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vals["k1"] != 1 || vals["k2"] != 2 {
		t.Fatalf("unexpected values: %#v", vals)
	}
	if calls != 1 {
		t.Fatalf("expected loader called once, got %d", calls)
	}
}

func TestGetManyAllCached(t *testing.T) {
	c := NewCacher[string, int]()
	_, _ = c.Get(context.Background(), "k1", func(ctx context.Context) (int, error) {
		return 1, nil
	})
	_, _ = c.Get(context.Background(), "k2", func(ctx context.Context) (int, error) {
		return 2, nil
	})

	calls := 0
	vals, err := c.GetMany(context.Background(), []string{"k1", "k2"}, func(ctx context.Context) (map[string]int, error) {
		calls++
		return map[string]int{"k1": 10, "k2": 20}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vals["k1"] != 1 || vals["k2"] != 2 {
		t.Fatalf("unexpected values: %#v", vals)
	}
	if calls != 0 {
		t.Fatalf("expected loader not called, got %d", calls)
	}
}

func TestGetManyLoaderError(t *testing.T) {
	c := NewCacher[string, int]()
	_, _ = c.Get(context.Background(), "k1", func(ctx context.Context) (int, error) {
		return 1, nil
	})

	_, err := c.GetMany(context.Background(), []string{"k1", "k2"}, func(ctx context.Context) (map[string]int, error) {
		return nil, context.DeadlineExceeded
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestNewCacherOptions(t *testing.T) {
	c := NewCacher(func(opts *options[string, int]) {
		opts.Capacity = 10
		opts.Ttl = 10 * time.Millisecond
	})

	_, err := c.Get(context.Background(), "k1", func(ctx context.Context) (int, error) {
		return 5, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
