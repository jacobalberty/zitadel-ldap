package zitadel

import (
	"context"
	"fmt"
	"strings"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	objectv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object/v2"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	userv2 "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
	"google.golang.org/grpc"
)

type userLister interface {
	ListUsers(ctx context.Context, req *userv2.ListUsersRequest, opts ...grpc.CallOption) (*userv2.ListUsersResponse, error)
}

type grantLister interface {
	ListUserGrants(ctx context.Context, req *management.ListUserGrantRequest, opts ...grpc.CallOption) (*management.ListUserGrantResponse, error)
}

type projectLister interface {
	ListProjects(ctx context.Context, req *management.ListProjectsRequest, opts ...grpc.CallOption) (*management.ListProjectsResponse, error)
}

type roleLister interface {
	ListProjectRoles(ctx context.Context, req *management.ListProjectRolesRequest, opts ...grpc.CallOption) (*management.ListProjectRolesResponse, error)
}

type metadataLister interface {
	ListUserMetadata(ctx context.Context, req *management.ListUserMetadataRequest, opts ...grpc.CallOption) (*management.ListUserMetadataResponse, error)
}

func (q *querier) ListUsers(ctx context.Context) (*zclient.UserResults, error) {
	key := CacheKey{
		Type: CacheKeyTypeUsers,
		ID:   "all",
	}

	return q.usersCache.Get(ctx, key, func(ctx context.Context) (*zclient.UserResults, error) {
		return q.fetchAllUsers(ctx)
	})
}

func (q *querier) FindUserByName(ctx context.Context, name string) (*zclient.UserResults, error) {
	allUsers, err := q.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for _, u := range allUsers.Result {
		if u.Human != nil && u.Username == name {
			return &zclient.UserResults{
				Result: []zclient.User{u},
			}, nil
		}
	}

	return &zclient.UserResults{Result: []zclient.User{}}, nil
}

func (q *querier) FindUserByMail(ctx context.Context, mail string) (*zclient.UserResults, error) {
	allUsers, err := q.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for _, u := range allUsers.Result {
		if u.Human != nil && u.Human.Email.Email == mail {
			return &zclient.UserResults{
				Result: []zclient.User{u},
			}, nil
		}
	}

	return &zclient.UserResults{Result: []zclient.User{}}, nil
}

func (q *querier) ListGrants(ctx context.Context) (*zclient.GrantResults, error) {
	key := CacheKey{
		Type: CacheKeyTypeGrants,
		ID:   "all",
	}

	return q.grantsCache.Get(ctx, key, func(ctx context.Context) (*zclient.GrantResults, error) {
		return q.fetchAllGrants(ctx)
	})
}

func (q *querier) ListProjects(ctx context.Context) (*zclient.ProjectResults, error) {
	key := CacheKey{
		Type: CacheKeyTypeProjects,
		ID:   "all",
	}

	return q.projectsCache.Get(ctx, key, func(ctx context.Context) (*zclient.ProjectResults, error) {
		return q.fetchAllProjects(ctx)
	})
}

func (q *querier) ListRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
	key := CacheKey{
		Type: CacheKeyTypeRoles,
		ID:   projectID,
	}

	return q.rolesCache.Get(ctx, key, func(ctx context.Context) (*zclient.RoleResults, error) {
		return q.fetchRoles(ctx, projectID)
	})
}

func (q *querier) ListMetadata(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
	key := CacheKey{
		Type: CacheKeyTypeMetadata,
		ID:   userID,
	}

	return q.metadataCache.Get(ctx, key, func(ctx context.Context) (*zclient.MetadataResults, error) {
		return q.fetchMetadata(ctx, userID)
	})
}

// fetchAllUsers retrieves all users from Zitadel with pagination
func (q *querier) fetchAllUsers(ctx context.Context) (*zclient.UserResults, error) {
	return fetchAllUsersWithService(ctx, q.zitadelClient.UserServiceV2(), q.ListGrants)
}

func fetchAllUsersWithService(ctx context.Context, userService userLister, listGrants func(context.Context) (*zclient.GrantResults, error)) (*zclient.UserResults, error) {
	allUsers, err := paginate(ctx, "ListUsers", "users",
		func(ctx context.Context, offset uint64, limit uint32) (rawPage[*userv2.User], error) {
			resp, err := userService.ListUsers(ctx, &userv2.ListUsersRequest{
				Query: &objectv2.ListQuery{Offset: offset, Limit: limit, Asc: true},
			})
			if err != nil {
				return rawPage[*userv2.User]{}, err
			}
			p := rawPage[*userv2.User]{items: resp.Result}
			if resp.Details != nil {
				p.total, p.hasTotal = resp.Details.TotalResult, true
			}
			return p, nil
		}, convertSDKUserToUser)
	if err != nil {
		return nil, err
	}

	grants, err := listGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list grants: %w", err)
	}

	userGrants := make(map[string][]string)
	for _, grant := range grants.Result {
		userGrants[grant.UserID] = append(userGrants[grant.UserID], grant.RoleKeys...)
	}

	for i := range allUsers {
		if allUsers[i].Human != nil {
			allUsers[i].Human.Groups = userGrants[allUsers[i].UserID]
		}
	}

	return &zclient.UserResults{
		Result: allUsers,
		Details: zclient.Details{
			TotalResult: fmt.Sprintf("%d", len(allUsers)),
		},
	}, nil
}

// fetchAllGrants retrieves all user grants from Zitadel with pagination
func (q *querier) fetchAllGrants(ctx context.Context) (*zclient.GrantResults, error) {
	return fetchAllGrantsWithService(ctx, q.zitadelClient.ManagementService())
}

func fetchAllGrantsWithService(ctx context.Context, mgmtService grantLister) (*zclient.GrantResults, error) {
	allGrants, err := paginate(ctx, "ListUserGrants", "grants",
		func(ctx context.Context, offset uint64, limit uint32) (rawPage[*user.UserGrant], error) {
			resp, err := mgmtService.ListUserGrants(ctx, &management.ListUserGrantRequest{
				Query: &object.ListQuery{Offset: offset, Limit: limit, Asc: true},
			})
			if err != nil {
				return rawPage[*user.UserGrant]{}, err
			}
			p := rawPage[*user.UserGrant]{items: resp.Result}
			if resp.Details != nil {
				p.total, p.hasTotal = resp.Details.TotalResult, true
			}
			return p, nil
		}, convertSDKGrantToGrant)
	if err != nil {
		return nil, err
	}

	return &zclient.GrantResults{
		Result: allGrants,
		Details: zclient.Details{
			TotalResult: fmt.Sprintf("%d", len(allGrants)),
		},
	}, nil
}

// fetchAllProjects retrieves all projects from Zitadel with pagination
func (q *querier) fetchAllProjects(ctx context.Context) (*zclient.ProjectResults, error) {
	return fetchAllProjectsWithService(ctx, q.zitadelClient.ManagementService())
}

func fetchAllProjectsWithService(ctx context.Context, mgmtService projectLister) (*zclient.ProjectResults, error) {
	all, err := paginate(ctx, "ListProjects", "projects",
		func(ctx context.Context, offset uint64, limit uint32) (rawPage[*project.Project], error) {
			resp, err := mgmtService.ListProjects(ctx, &management.ListProjectsRequest{
				Query: &object.ListQuery{Offset: offset, Limit: limit, Asc: true},
			})
			if err != nil {
				return rawPage[*project.Project]{}, err
			}
			p := rawPage[*project.Project]{items: resp.Result}
			if resp.Details != nil {
				p.total, p.hasTotal = resp.Details.TotalResult, true
			}
			return p, nil
		}, convertSDKProjectToProjectResult)
	if err != nil {
		return nil, err
	}

	return &zclient.ProjectResults{
		Result: all,
		Details: zclient.Details{
			TotalResult: fmt.Sprintf("%d", len(all)),
		},
	}, nil
}

// fetchRoles retrieves all roles for a project from Zitadel with pagination
func (q *querier) fetchRoles(ctx context.Context, projectID string) (*zclient.RoleResults, error) {
	return fetchRolesWithService(ctx, q.zitadelClient.ManagementService(), projectID)
}

func fetchRolesWithService(ctx context.Context, mgmtService roleLister, projectID string) (*zclient.RoleResults, error) {
	all, err := paginate(ctx, "ListProjectRoles", "roles for project "+projectID,
		func(ctx context.Context, offset uint64, limit uint32) (rawPage[*project.Role], error) {
			resp, err := mgmtService.ListProjectRoles(ctx, &management.ListProjectRolesRequest{
				ProjectId: projectID,
				Query:     &object.ListQuery{Offset: offset, Limit: limit, Asc: true},
			})
			if err != nil {
				return rawPage[*project.Role]{}, err
			}
			p := rawPage[*project.Role]{items: resp.Result}
			if resp.Details != nil {
				p.total, p.hasTotal = resp.Details.TotalResult, true
			}
			return p, nil
		}, convertSDKRoleToRoleResult)
	if err != nil {
		return nil, err
	}

	return &zclient.RoleResults{
		Result: all,
		Details: zclient.Details{
			TotalResult: fmt.Sprintf("%d", len(all)),
		},
	}, nil
}

// fetchMetadata retrieves metadata for a user from Zitadel with pagination
func (q *querier) fetchMetadata(ctx context.Context, userID string) (*zclient.MetadataResults, error) {
	return fetchMetadataWithService(ctx, q.zitadelClient.ManagementService(), userID)
}

func fetchMetadataWithService(ctx context.Context, mgmtService metadataLister, userID string) (*zclient.MetadataResults, error) {
	all, err := paginate(ctx, "ListUserMetadata", "metadata for user "+userID,
		func(ctx context.Context, offset uint64, limit uint32) (rawPage[*metadata.Metadata], error) {
			resp, err := mgmtService.ListUserMetadata(ctx, &management.ListUserMetadataRequest{
				Id:    userID,
				Query: &object.ListQuery{Offset: offset, Limit: limit, Asc: true},
			})
			if err != nil {
				return rawPage[*metadata.Metadata]{}, err
			}
			p := rawPage[*metadata.Metadata]{items: resp.Result}
			if resp.Details != nil {
				p.total, p.hasTotal = resp.Details.TotalResult, true
			}
			return p, nil
		}, convertSDKMetadataToMetadataResult)
	if err != nil {
		return nil, err
	}

	return &zclient.MetadataResults{
		Result: all,
		Details: zclient.Details{
			TotalResult: fmt.Sprintf("%d", len(all)),
		},
	}, nil
}

// classifyError wraps gRPC errors and determines if they're retryable
func classifyError(operation string, err error) error {
	if err == nil {
		return nil
	}

	// Extract gRPC status code
	st, ok := status.FromError(err)
	if !ok {
		// Not a gRPC error, treat as non-retryable internal error
		return apperrors.NewZitadelError(operation, err, false)
	}

	var wrappedErr error
	var retryable bool

	switch st.Code() {
	case codes.OK:
		return nil

	case codes.Canceled, codes.DeadlineExceeded:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrTimeout, st.Message())
		retryable = true

	case codes.NotFound:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrNotFound, st.Message())
		retryable = false

	case codes.AlreadyExists:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrAlreadyExists, st.Message())
		retryable = false

	case codes.Aborted:
		// Concurrent-modification conflicts are transient.
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrServiceUnavailable, st.Message())
		retryable = true

	case codes.Unauthenticated:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrUnauthorized, st.Message())
		retryable = false

	case codes.PermissionDenied:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrForbidden, st.Message())
		retryable = false

	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrInvalidInput, st.Message())
		retryable = false

	case codes.ResourceExhausted:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrRateLimited, st.Message())
		retryable = true

	case codes.Unavailable:
		wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrServiceUnavailable, st.Message())
		retryable = true

	case codes.Internal, codes.Unknown, codes.DataLoss:
		// Check if error message indicates a transient issue
		msg := strings.ToLower(st.Message())
		if strings.Contains(msg, "connection") ||
			strings.Contains(msg, "timeout") ||
			strings.Contains(msg, "temporary") {
			wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrServiceUnavailable, st.Message())
			retryable = true
		} else {
			wrappedErr = fmt.Errorf("%w: %s", apperrors.ErrInternal, st.Message())
			retryable = false
		}

	default:
		// Unknown error code, treat as non-retryable
		wrappedErr = fmt.Errorf("%w: code=%s, msg=%s", apperrors.ErrInternal, st.Code(), st.Message())
		retryable = false
	}

	return apperrors.NewZitadelError(operation, wrappedErr, retryable)
}
