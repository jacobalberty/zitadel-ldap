package zitadel

import "errors"

var (
	ErrStoreUninitialized = errors.New("zitadel store is not initialized")
	ErrNotImplemented     = errors.New("not implemented")
)
