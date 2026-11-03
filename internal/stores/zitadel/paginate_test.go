package zitadel

import (
	"context"
	"fmt"
	"testing"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	"google.golang.org/grpc"
)

// cappedGrantService serves from a fixed dataset but never returns more than
// `cap` items per page, regardless of the requested limit.
type cappedGrantService struct {
	total int
	cap   int
	calls int
}

func (f *cappedGrantService) ListUserGrants(ctx context.Context, req *management.ListUserGrantRequest, opts ...grpc.CallOption) (*management.ListUserGrantResponse, error) {
	f.calls++
	off := int(req.Query.Offset)
	end := min(off+int(req.Query.Limit), off+f.cap)
	if end > f.total {
		end = f.total
	}
	var res []*user.UserGrant
	for i := off; i < end; i++ {
		res = append(res, &user.UserGrant{UserId: fmt.Sprintf("u%d", i)})
	}
	return &management.ListUserGrantResponse{
		Details: &object.ListDetails{TotalResult: uint64(f.total)},
		Result:  res,
	}, nil
}

func TestPaginationSurvivesServerPageCap(t *testing.T) {
	svc := &cappedGrantService{total: 230, cap: 50}
	res, err := fetchAllGrantsWithService(context.Background(), svc)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Result) != 230 {
		t.Fatalf("got %d grants, want 230 (items skipped when server caps page size)", len(res.Result))
	}
	seen := map[string]bool{}
	for _, g := range res.Result {
		if seen[g.UserID] {
			t.Fatalf("duplicate %s", g.UserID)
		}
		seen[g.UserID] = true
	}
}

// A server that reports more results than it will ever return must not loop forever.
func TestPaginationStopsOnEmptyPage(t *testing.T) {
	svc := &cappedGrantService{total: 10, cap: 5}
	// Claim 1000 total but serve only 10.
	liar := &liarGrantService{inner: svc}
	res, err := fetchAllGrantsWithService(context.Background(), liar)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Result) != 10 {
		t.Fatalf("got %d", len(res.Result))
	}
}

type liarGrantService struct{ inner *cappedGrantService }

func (l *liarGrantService) ListUserGrants(ctx context.Context, req *management.ListUserGrantRequest, opts ...grpc.CallOption) (*management.ListUserGrantResponse, error) {
	r, err := l.inner.ListUserGrants(ctx, req, opts...)
	if r != nil {
		r.Details.TotalResult = 1000
	}
	return r, err
}
