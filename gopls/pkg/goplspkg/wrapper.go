// Copyright 2025 The Ripples Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package goplspkg provides public wrappers around gopls internal packages.
// This allows external projects to use gopls functionality without directly
// importing internal packages, which is not allowed by Go's visibility rules.
package goplspkg

import (
	"context"

	"golang.org/x/tools/gopls/internal/cache"
	"golang.org/x/tools/gopls/internal/protocol"
	"golang.org/x/tools/gopls/internal/server"
	"golang.org/x/tools/gopls/internal/settings"
	"golang.org/x/tools/internal/memoize"
)

// Cache wraps gopls internal cache.Cache
type Cache struct {
	internal *cache.Cache
}

// Session wraps gopls internal cache.Session
type Session struct {
	internal *cache.Session
}

// Server is an alias for protocol.Server
type Server = protocol.Server

// ClientCloser is an alias for protocol.ClientCloser
type ClientCloser = protocol.ClientCloser

// Options wraps gopls internal settings.Options
type Options = settings.Options

// NewCache creates a new Cache instance.
// The store parameter may be nil, in which case a new store is created.
func NewCache(store *memoize.Store) *Cache {
	return &Cache{
		internal: cache.New(store),
	}
}

// NewSession creates a new Session with the given cache.
func NewSession(ctx context.Context, c *Cache) *Session {
	return &Session{
		internal: cache.NewSession(ctx, c.internal),
	}
}

// NewServer creates an LSP server and binds it to handle incoming client
// messages on the supplied stream.
func NewServer(session *Session, client ClientCloser, options *Options) Server {
	return server.New(session.internal, client, options)
}

// DefaultOptions returns the default options for gopls.
// The optionsFunc parameter can be used to customize the options.
func DefaultOptions(optionsFunc func(*Options)) *Options {
	return settings.DefaultOptions(optionsFunc)
}

// Internal returns the internal session for advanced use cases.
// Use with caution as the internal API may change.
func (s *Session) Internal() *cache.Session {
	return s.internal
}

// Internal returns the internal cache for advanced use cases.
// Use with caution as the internal API may change.
func (c *Cache) Internal() *cache.Cache {
	return c.internal
}
