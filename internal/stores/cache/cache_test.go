package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

func TestGetSingleFlight(t *testing.T) {
	c := NewCacher[string, int]()
	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			v, err := c.Get(context.Background(), "k", func(ctx context.Context) (int, error) {
				calls.Add(1)
				<-release
				return 9, nil
			})
			if err != nil || v != 9 {
				t.Errorf("v=%d err=%v", v, err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("loader called %d times, want 1", n)
	}
}

func TestClearDuringLoadDoesNotRepopulateStale(t *testing.T) {
	c := NewCacher[string, int]()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Get(context.Background(), "k", func(ctx context.Context) (int, error) {
			close(started)
			<-release
			return 1, nil // pre-write data
		})
	}()
	<-started
	c.Clear() // a write happens while the load is in flight
	close(release)
	<-done

	v, err := c.Get(context.Background(), "k", func(ctx context.Context) (int, error) { return 2, nil })
	if err != nil || v != 2 {
		t.Fatalf("stale value served after Clear: v=%d err=%v", v, err)
	}
}

func TestCancelledCallerDoesNotFailOthers(t *testing.T) {
	c := NewCacher[string, int]()
	release := make(chan struct{})
	ctx1, cancel1 := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() {
		_, _ = c.Get(ctx1, "k", func(ctx context.Context) (int, error) {
			close(started)
			<-release
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			return 5, nil
		})
	}()
	<-started
	cancel1()
	res := make(chan int, 1)
	go func() {
		v, _ := c.Get(context.Background(), "k", func(ctx context.Context) (int, error) { return -1, nil })
		res <- v
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)
	if v := <-res; v != 5 {
		t.Fatalf("second caller got %d, want 5", v)
	}
}

func TestLoaderErrorNotCached(t *testing.T) {
	c := NewCacher[string, int]()
	_, err := c.Get(context.Background(), "k", func(ctx context.Context) (int, error) { return 0, errors.New("x") })
	if err == nil {
		t.Fatal("expected error")
	}
	v, err := c.Get(context.Background(), "k", func(ctx context.Context) (int, error) { return 3, nil })
	if err != nil || v != 3 {
		t.Fatalf("v=%d err=%v", v, err)
	}
}

func TestConcurrentGetAndClearRace(t *testing.T) {
	c := NewCacher[int, int]()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range 200 {
				if g%4 == 0 {
					c.Clear()
					continue
				}
				_, _ = c.Get(context.Background(), i%5, func(ctx context.Context) (int, error) { return i, nil })
			}
		}(g)
	}
	wg.Wait()
}
