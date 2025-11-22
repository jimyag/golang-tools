// Package ripplesapi provides a public API to access gopls internal functionality
// for the ripples project
package ripplesapi

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/tools/gopls/internal/cache"
	"golang.org/x/tools/gopls/internal/file"
	"golang.org/x/tools/gopls/internal/golang"
	"golang.org/x/tools/gopls/internal/protocol"
	"golang.org/x/tools/gopls/internal/settings"
)

// Position represents a position in a source file
type Position struct {
	Filename string
	Line     int // 1-based
	Column   int // 1-based
}

// CallNode represents a node in the call chain
type CallNode struct {
	FunctionName string
	PackagePath  string
}

// CallPath represents a call path from a changed symbol to a main function
type CallPath struct {
	BinaryName string
	MainURI    string
	Path       []CallNode
}

// DirectTracer directly uses gopls internal packages for call hierarchy analysis
type DirectTracer struct {
	session  *cache.Session
	view     *cache.View
	snapshot *cache.Snapshot
	release  func()
	rootPath string
	ctx      context.Context
}

// NewDirectTracer creates a new DirectTracer
func NewDirectTracer(ctx context.Context, rootPath string) (*DirectTracer, error) {
	// 1. Create cache
	c := cache.New(nil)

	// 2. Create session
	session := cache.NewSession(ctx, c)

	// 3. Create folder with options
	folder, err := createFolder(ctx, rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create folder: %w", err)
	}

	// 4. Create view and snapshot
	view, snapshot, release, err := session.NewView(ctx, folder)
	if err != nil {
		return nil, fmt.Errorf("failed to create view: %w", err)
	}

	return &DirectTracer{
		session:  session,
		view:     view,
		snapshot: snapshot,
		release:  release,
		rootPath: rootPath,
		ctx:      ctx,
	}, nil
}

// createFolder creates a Folder with default options
func createFolder(ctx context.Context, rootPath string) (*cache.Folder, error) {
	absPath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	uri := protocol.URIFromPath(absPath)

	// Use default options
	opts := settings.DefaultOptions()

	// Fetch Go environment
	goEnv, err := cache.FetchGoEnv(ctx, uri, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Go environment: %w", err)
	}

	return &cache.Folder{
		Dir:     uri,
		Name:    filepath.Base(absPath),
		Options: opts,
		Env:     *goEnv,
	}, nil
}

// Close releases resources
func (t *DirectTracer) Close() error {
	if t.release != nil {
		t.release()
	}
	return nil
}

// TraceToMain traces a symbol to all main functions that call it
func (t *DirectTracer) TraceToMain(pos Position, functionName string) ([]CallPath, error) {
	// Convert file path to URI
	uri := protocol.URIFromPath(pos.Filename)

	// Get file handle from snapshot
	fh, err := t.snapshot.ReadFile(t.ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to find the exact position of the function name
	adjustedPos, err := t.findFunctionNamePosition(fh, pos, functionName)
	if err != nil {
		// Fall back to original position if we can't find it
		adjustedPos = pos
	}

	// Convert position to protocol.Position (0-based)
	position := protocol.Position{
		Line:      uint32(adjustedPos.Line - 1),
		Character: uint32(adjustedPos.Column - 1),
	}

	// Call gopls internal PrepareCallHierarchy
	items, err := golang.PrepareCallHierarchy(t.ctx, t.snapshot, fh, position)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare call hierarchy: %w", err)
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no call hierarchy items found for %s at %s:%d:%d",
			functionName, pos.Filename, pos.Line, pos.Column)
	}

	// Trace incoming calls recursively
	var paths []CallPath
	visited := make(map[string]bool)
	seenBinaries := make(map[string]bool)

	for _, item := range items {
		initialNode := CallNode{
			FunctionName: item.Name,
			PackagePath:  extractPackageFromItem(item),
		}
		t.traceIncomingCalls(item, []CallNode{initialNode}, visited, &paths, seenBinaries)
	}

	return paths, nil
}

// extractPackageFromItem extracts package path from call hierarchy item
func extractPackageFromItem(item protocol.CallHierarchyItem) string {
	// item.Detail format: "package/path • filename.go"
	if item.Detail != "" {
		parts := strings.Split(item.Detail, " • ")
		if len(parts) >= 1 {
			return parts[0]
		}
	}
	return ""
}

// traceIncomingCalls recursively traces incoming calls
func (t *DirectTracer) traceIncomingCalls(
	item protocol.CallHierarchyItem,
	currentPath []CallNode,
	visited map[string]bool,
	paths *[]CallPath,
	seenBinaries map[string]bool,
) {
	// Create a unique key for this item
	key := fmt.Sprintf("%s:%d:%d", item.URI, item.Range.Start.Line, item.Range.Start.Character)

	if visited[key] {
		return
	}
	visited[key] = true

	// Check if this is a main function
	if isMainFunction(item) {
		binaryName := getBinaryName(item)

		// Deduplicate by binary name
		if seenBinaries[binaryName] {
			return
		}
		seenBinaries[binaryName] = true

		// Found a path to main
		completePath := make([]CallNode, len(currentPath))
		copy(completePath, currentPath)

		*paths = append(*paths, CallPath{
			BinaryName: binaryName,
			MainURI:    string(item.URI),
			Path:       completePath,
		})
		return
	}

	// Get file handle for incoming calls
	fh, err := t.snapshot.ReadFile(t.ctx, item.URI)
	if err != nil {
		fmt.Printf("Warning: failed to read file %s: %v\n", item.URI, err)
		return
	}

	// Get incoming calls using gopls internal API
	incomingCalls, err := golang.IncomingCalls(t.ctx, t.snapshot, fh, item.Range.Start)
	if err != nil {
		fmt.Printf("Warning: failed to get incoming calls for %s: %v\n", item.Name, err)
		return
	}

	if len(incomingCalls) == 0 {
		// Dead end - no callers found
		return
	}

	// Recursively trace each caller
	for _, call := range incomingCalls {
		callerNode := CallNode{
			FunctionName: call.From.Name,
			PackagePath:  extractPackageFromItem(call.From),
		}

		// Check for cross-service calls
		if isCrossServiceCall(callerNode.PackagePath, currentPath) {
			continue
		}

		newPath := append([]CallNode{callerNode}, currentPath...)
		t.traceIncomingCalls(call.From, newPath, visited, paths, seenBinaries)
	}
}

// isCrossServiceCall checks if a call crosses service boundaries
func isCrossServiceCall(callerPkg string, currentPath []CallNode) bool {
	if len(currentPath) == 0 {
		return false
	}

	callerService := extractServiceName(callerPkg)

	for _, node := range currentPath {
		nodeService := extractServiceName(node.PackagePath)

		if callerService != "" && nodeService != "" && callerService != nodeService {
			if !isCommonPackage(node.PackagePath) {
				return true
			}
		}
	}

	return false
}

// extractServiceName extracts the service name from a package path
func extractServiceName(pkgPath string) string {
	if strings.HasPrefix(pkgPath, "cmd/") {
		parts := strings.Split(pkgPath, "/")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	if strings.HasPrefix(pkgPath, "internal/") {
		parts := strings.Split(pkgPath, "/")
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	return ""
}

// isCommonPackage checks if a package is a common/shared package
func isCommonPackage(pkgPath string) bool {
	commonPrefixes := []string{
		"pkg/",
		"api/",
		"common/",
		"shared/",
		"lib/",
	}

	for _, prefix := range commonPrefixes {
		if strings.HasPrefix(pkgPath, prefix) {
			return true
		}
	}

	return false
}

// isMainFunction checks if an item is a main function
func isMainFunction(item protocol.CallHierarchyItem) bool {
	if item.Name != "main" {
		return false
	}

	uri := string(item.URI)
	if !strings.HasPrefix(uri, "file://") {
		return false
	}

	filePath := strings.TrimPrefix(uri, "file://")
	dir := filepath.Dir(filePath)

	return strings.Contains(dir, "/cmd/") || filepath.Base(dir) == "main"
}

// getBinaryName extracts the binary name from a main function's item
func getBinaryName(item protocol.CallHierarchyItem) string {
	uri := string(item.URI)
	if !strings.HasPrefix(uri, "file://") {
		return "unknown"
	}

	filePath := strings.TrimPrefix(uri, "file://")
	dir := filepath.Dir(filePath)

	parts := strings.Split(dir, "/cmd/")
	if len(parts) == 2 {
		return filepath.Base(parts[1])
	}

	return filepath.Base(dir)
}

// findFunctionNamePosition tries to find the exact position of the function name
// This helps when the initial position points to "func" keyword or receiver
func (t *DirectTracer) findFunctionNamePosition(fh file.Handle, pos Position, functionName string) (Position, error) {
	content, err := fh.Content()
	if err != nil {
		return pos, err
	}

	lines := strings.Split(string(content), "\n")
	if pos.Line < 1 || pos.Line > len(lines) {
		return pos, fmt.Errorf("line number out of range")
	}

	// Search in the current line and a few lines around it
	searchStart := pos.Line - 1
	if searchStart < 0 {
		searchStart = 0
	}
	searchEnd := pos.Line + 2
	if searchEnd > len(lines) {
		searchEnd = len(lines)
	}

	// Look for the function name in nearby lines
	for i := searchStart; i < searchEnd; i++ {
		line := lines[i]
		// Try to find the function name
		// Patterns: "func foo", "func (r *Receiver) foo", "func foo[T any]"
		idx := strings.Index(line, functionName)
		if idx != -1 {
			// Check if this looks like a function declaration
			// Should have "func" before it
			beforeName := line[:idx]
			if strings.Contains(beforeName, "func") {
				// Found it! Return 1-based position
				return Position{
					Filename: pos.Filename,
					Line:     i + 1,
					Column:   idx + 1,
				}, nil
			}
		}
	}

	// Couldn't find it, return original position
	return pos, fmt.Errorf("function name not found in nearby lines")
}
