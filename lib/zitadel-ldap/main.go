package main

import (
	"github.com/glauth/glauth/v2/pkg/handler"

	ghandler "github.com/jacobalberty/zitadel-ldap/internal/handler"
)

// NewZitadelHandler is the entry point for the GLAuth plugin
// GLAuth will call this function to create the handler
func NewZitadelHandler(opts ...handler.Option) handler.Handler {
	return ghandler.NewZitadelHandler(opts...)
}
