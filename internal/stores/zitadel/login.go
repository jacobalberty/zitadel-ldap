package zitadel

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
	"github.com/jacobalberty/zitadel-ldap/internal/retry"
)

func (q *querier) Login(ctx context.Context, username, password string) (bool, error) {
	key := CacheKey{
		Type: CacheKeyTypeUser,
		ID:   q.hashLogin(username, password),
	}

	return q.loginCache.Get(ctx, key, func(ctx context.Context) (bool, error) {
		sessionClient := q.zitadelClient.SessionServiceV2()
		sesReq := &session.CreateSessionRequest{
			Checks: &session.Checks{
				User: &session.CheckUser{
					Search: &session.CheckUser_LoginName{
						LoginName: username,
					},
				},
				Password: &session.CheckPassword{
					Password: password,
				},
			},
		}

		// Use retry logic for session creation
		retryConfig := retry.DefaultConfig()
		sesRes, err := retry.Do(ctx, retryConfig, func() (*session.CreateSessionResponse, error) {
			resp, err := sessionClient.CreateSession(ctx, sesReq)
			if err != nil {
				return nil, classifyLoginError(err)
			}
			return resp, nil
		})

		if err != nil {
			// Check if it's an authentication failure (non-retryable)
			if apperrors.IsUnauthorized(err) {
				return false, nil // Invalid credentials, not an error
			}
			return false, fmt.Errorf("failed to create session: %w", err)
		}

		return sesRes.SessionToken != "", nil
	})
}

func (q *querier) hashLogin(username, password string) string {
	h := sha256.New()
	h.Write([]byte(username + password))
	return string(h.Sum(nil))
}

// classifyLoginError determines if a login error is retryable
func classifyLoginError(err error) error {
	// Use the same classification logic as other operations
	classified := classifyError("CreateSession", err)

	// For login, treat authentication errors specially
	if apperrors.IsUnauthorized(classified) {
		// Invalid credentials shouldn't be retried
		return apperrors.NewZitadelError("CreateSession", apperrors.ErrUnauthorized, false)
	}

	return classified
}
