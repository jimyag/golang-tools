// Copyright 2025 The Ripples Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package protocol re-exports gopls protocol types for external use.
package protocol

import (
	"golang.org/x/tools/gopls/internal/protocol"
)

// Re-export commonly used protocol types
type (
	DocumentURI                      = protocol.DocumentURI
	Position                         = protocol.Position
	Range                            = protocol.Range
	Location                         = protocol.Location
	TextDocumentIdentifier           = protocol.TextDocumentIdentifier
	VersionedTextDocumentIdentifier  = protocol.VersionedTextDocumentIdentifier
	TextDocumentItem                 = protocol.TextDocumentItem
	CallHierarchyItem                = protocol.CallHierarchyItem
	CallHierarchyIncomingCall        = protocol.CallHierarchyIncomingCall
	CallHierarchyOutgoingCall        = protocol.CallHierarchyOutgoingCall
	CallHierarchyIncomingCallsParams = protocol.CallHierarchyIncomingCallsParams
	CallHierarchyOutgoingCallsParams = protocol.CallHierarchyOutgoingCallsParams
	CallHierarchyPrepareParams       = protocol.CallHierarchyPrepareParams
	DidOpenTextDocumentParams        = protocol.DidOpenTextDocumentParams
	DidCloseTextDocumentParams       = protocol.DidCloseTextDocumentParams
	ParamInitialize                  = protocol.ParamInitialize
	InitializeParams                 = protocol.InitializeParams
	InitializeResult                 = protocol.InitializeResult
	InitializedParams                = protocol.InitializedParams
	ClientCapabilities               = protocol.ClientCapabilities
	ServerCapabilities               = protocol.ServerCapabilities
	WorkspaceFolder                  = protocol.WorkspaceFolder
)

// Client interface re-export
type Client = protocol.Client

// Server interface re-export
type Server = protocol.Server

// ClientCloser interface re-export
type ClientCloser = protocol.ClientCloser
