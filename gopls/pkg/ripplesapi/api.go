// Package ripplesapi provides a public API for the ripples tool to access gopls functionality
package ripplesapi

import (
	"golang.org/x/tools/gopls/internal/ripplesapi"
)

// Re-export types from internal package
type Position = ripplesapi.Position
type CallNode = ripplesapi.CallNode
type CallPath = ripplesapi.CallPath
type DirectTracer = ripplesapi.DirectTracer

// NewDirectTracer creates a new DirectTracer
var NewDirectTracer = ripplesapi.NewDirectTracer
