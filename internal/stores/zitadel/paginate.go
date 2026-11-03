package zitadel

import (
	"context"
	"fmt"

	"github.com/jacobalberty/zitadel-ldap/internal/retry"
)

// pageSize is the page size requested from Zitadel. The server may return
// fewer items than requested (it can cap the page), so callers must advance
// by the number of items actually received, never by pageSize.
const pageSize uint32 = 100

// rawPage is one page of results from a list endpoint.
type rawPage[R any] struct {
	items    []R
	total    uint64 // total matching results, valid if hasTotal
	hasTotal bool
}

// paginate fetches every page and converts each item. fetch performs a single
// raw RPC; paginate adds retry, error classification and loop termination
// (end of data, empty page, or missing totals).
func paginate[R, T any](
	ctx context.Context,
	op, what string,
	fetch func(ctx context.Context, offset uint64, limit uint32) (rawPage[R], error),
	convert func(R) T,
) ([]T, error) {
	var out []T
	var offset uint64
	retryConfig := retry.DefaultConfig()

	for {
		p, err := retry.Do(ctx, retryConfig, func() (rawPage[R], error) {
			p, err := fetch(ctx, offset, pageSize)
			if err != nil {
				return p, classifyError(op, err)
			}
			return p, nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list %s at offset %d: %w", what, offset, err)
		}

		for _, item := range p.items {
			out = append(out, convert(item))
		}

		n := uint64(len(p.items))
		// An empty page ends the loop even if totals claim more: otherwise a
		// server that under-delivers would spin forever.
		if n == 0 || !p.hasTotal || offset+n >= p.total {
			return out, nil
		}
		offset += n
	}
}
