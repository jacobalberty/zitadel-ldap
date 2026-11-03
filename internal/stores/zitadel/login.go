package zitadel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/session/v2"

	apperrors "github.com/jacobalberty/zitadel-ldap/internal/errors"
	"github.com/jacobalberty/zitadel-ldap/internal/retry"
)

// defaultLoginCacheTTL is deliberately short: a cached success keeps a user
// authenticated even if their account is deleted/disabled or the password is
// changed directly in Zitadel.
const defaultLoginCacheTTL = 60 * time.Second

// loginHMACKey keys the login cache. It is random per process so cache keys
// are not an offline-attackable hash of the password.
var loginHMACKey = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(fmt.Errorf("cannot generate login cache key: %w", err))
	}
	return k
}()

// errLoginRejected is returned by the cache loader for bad credentials so
// failures are never cached.
var errLoginRejected = errors.New("login rejected")

// loginCacheTTL reads ZITADEL_LDAP_LOGIN_CACHE_TTL (Go duration, "0" disables caching).
func loginCacheTTL() time.Duration {
	v := os.Getenv("ZITADEL_LDAP_LOGIN_CACHE_TTL")
	if v == "" {
		return defaultLoginCacheTTL
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return defaultLoginCacheTTL
	}
	return d
}

func (q *querier) Login(ctx context.Context, username, password string) (bool, error) {
	key := CacheKey{
		Type: CacheKeyTypeUser,
		ID:   q.hashLogin(username, password),
	}

	ok, err := q.loginCache.Get(ctx, key, func(ctx context.Context) (bool, error) {
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
		// Creating a session is not idempotent; do not retry.
		retryConfig := retry.NoRetryConfig()
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
				return false, errLoginRejected // invalid credentials: never cached
			}
			return false, fmt.Errorf("failed to create session: %w", err)
		}

		if sesRes.SessionToken == "" {
			return false, errLoginRejected
		}
		return true, nil
	})
	if errors.Is(err, errLoginRejected) {
		return false, nil
	}
	return ok, err
}

// hashLogin returns an HMAC over the length-prefixed username and password.
// Length prefixes prevent ("bob","xsecret") colliding with ("bobx","secret").
func (q *querier) hashLogin(username, password string) string {
	h := hmac.New(sha256.New, loginHMACKey)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(username)))
	h.Write(n[:])
	h.Write([]byte(username))
	binary.BigEndian.PutUint64(n[:], uint64(len(password)))
	h.Write(n[:])
	h.Write([]byte(password))
	return string(h.Sum(nil))
}

// classifyLoginError determines if a login error is retryable
func classifyLoginError(err error) error {
	// Use the same classification logic as other operations
	classified := classifyError("CreateSession", err)

	// For login, treat authentication errors specially. Zitadel reports a bad
	// password, an unknown user or a locked account with different gRPC codes
	// depending on version/configuration; none of them is an operational error
	// and all must reach the client as "invalid credentials" (not as an
	// OperationsError, and without revealing which case applied).
	if apperrors.IsUnauthorized(classified) ||
		apperrors.IsNotFound(classified) ||
		apperrors.IsForbidden(classified) ||
		errors.Is(classified, apperrors.ErrInvalidInput) {
		// Invalid credentials shouldn't be retried
		return apperrors.NewZitadelError("CreateSession", apperrors.ErrUnauthorized, false)
	}

	return classified
}
