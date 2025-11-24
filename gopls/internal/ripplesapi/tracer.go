// Package ripplesapi provides a public API to access gopls internal functionality
// for the ripples project
package ripplesapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/tools/gopls/internal/cache"
	"golang.org/x/tools/gopls/internal/cache/metadata"
	"golang.org/x/tools/gopls/internal/cache/parsego"
	"golang.org/x/tools/gopls/internal/file"
	"golang.org/x/tools/gopls/internal/filecache"
	"golang.org/x/tools/gopls/internal/golang"
	"golang.org/x/tools/gopls/internal/protocol"
	"golang.org/x/tools/gopls/internal/settings"
)

var log = initLogger()

func initLogger() zerolog.Logger {
	// Default to disabled level (higher than all log levels)
	level := zerolog.Disabled

	// Allow enabling debug logs via environment variable
	if os.Getenv("RIPPLES_DEBUG") == "1" || os.Getenv("RIPPLES_DEBUG") == "true" {
		level = zerolog.DebugLevel
	}

	return zerolog.New(os.Stderr).Level(level)
}

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
	session            *cache.Session
	view               *cache.View
	snapshot           *cache.Snapshot
	release            func()
	rootPath           string
	ctx                context.Context
	globalSeenBinaries sync.Map // map[string]bool - Shared across all traces to early-exit
	callCache          sync.Map // map[string][]protocol.CallHierarchyIncomingCall - Cache for IncomingCalls
	traceCache         sync.Map // map[string][]CallPath - Cache entire TraceToMain results
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

	dt := &DirectTracer{
		session:  session,
		view:     view,
		snapshot: snapshot,
		release:  release,
		rootPath: rootPath,
		ctx:      ctx,
	}
	// sync.Map doesn't need initialization
	return dt, nil
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
	// Generate cache key for both in-memory and persistent cache
	cacheKey := fmt.Sprintf("%s:%d:%d:%s", pos.Filename, pos.Line, pos.Column, functionName)

	// Check persistent cache first (survives across runs)
	persistentCacheKey := sha256.Sum256([]byte(cacheKey))
	if cached, err := filecache.Get("ripples-trace", persistentCacheKey); err == nil {
		var paths []CallPath
		if err := json.Unmarshal(cached, &paths); err == nil {
			log.Debug().Str("key", cacheKey).Msg("Using PERSISTENT cached trace")
			// Also store in in-memory cache for faster subsequent access
			t.traceCache.Store(cacheKey, paths)
			return paths, nil
		}
	}

	// Check in-memory trace cache (function-level caching)
	if cached, ok := t.traceCache.Load(cacheKey); ok {
		log.Debug().Str("key", cacheKey).Msg("Using in-memory cached TraceToMain result")
		return cached.([]CallPath), nil
	}

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

	// Debug: print what PrepareCallHierarchy found
	for i, item := range items {
		log.Debug().Int("index", i).Str("name", item.Name).Interface("kind", item.Kind).
			Msg("PrepareCallHierarchy found item")
	}

	// Trace incoming calls recursively with depth limit
	const maxDepth = 30 // Prevent runaway recursion (reduced from 50 for better performance)
	var paths []CallPath
	visited := make(map[string]bool)
	seenBinaries := make(map[string]bool)

	for _, item := range items {
		initialNode := CallNode{
			FunctionName: item.Name,
			PackagePath:  extractPackageFromItem(item),
		}
		// Check if the initial symbol is in a common package
		startedInCommonPkg := isCommonPackage(initialNode.PackagePath)
		t.traceIncomingCallsWithDepth(item, []CallNode{initialNode}, visited, &paths, seenBinaries, startedInCommonPkg, 0, maxDepth)
	}

	// Store in both caches before returning
	t.traceCache.Store(cacheKey, paths)
	log.Debug().Str("key", cacheKey).Int("paths", len(paths)).Msg("Cached TraceToMain result in memory")

	// Store in persistent cache (survives across runs)
	if data, err := json.Marshal(paths); err == nil {
		persistentCacheKey := sha256.Sum256([]byte(cacheKey))
		if err := filecache.Set("ripples-trace", persistentCacheKey, data); err == nil {
			log.Debug().Str("key", cacheKey).Msg("Stored trace in PERSISTENT cache")
		} else {
			log.Warn().Err(err).Msg("Failed to store in persistent cache")
		}
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

// extractServiceIdentifier extracts a service identifier from a package path
// For example:
//   - "example.com/project/cmd/service-a" -> "service-a"
//   - "example.com/project/internal/service-b" -> "service-b"
//   - "example.com/project/internal/bill/server" -> "bill"
// This helps identify which service a package belongs to
func extractServiceIdentifier(pkgPath string) string {
	// Split by /
	parts := strings.Split(pkgPath, "/")

	// Look for service-identifying segments
	// Common patterns: cmd/xxx, internal/xxx, services/xxx
	for i, part := range parts {
		// Check if this is a service-related directory
		if part == "cmd" || part == "internal" || part == "services" || part == "apps" {
			// The next part is likely the service name
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	return ""
}

// extractPackageFromURI extracts the package path by querying gopls for the URI's package
func (t *DirectTracer) extractPackageFromURI(uri protocol.DocumentURI) string {
	// Get package metadata for this file
	// The third parameter (includeIntermediateTestVariants) should be false
	pkgs, err := t.snapshot.MetadataForFile(t.ctx, uri, false)
	if err != nil || len(pkgs) == 0 {
		return ""
	}

	// Return the first package's PkgPath (import path)
	return string(pkgs[0].PkgPath)
}

// traceIncomingCallsWithDepth recursively traces incoming calls with depth limit
func (t *DirectTracer) traceIncomingCallsWithDepth(
	item protocol.CallHierarchyItem,
	currentPath []CallNode,
	visited map[string]bool,
	paths *[]CallPath,
	seenBinaries map[string]bool,
	startedInCommonPkg bool, // true if the original changed symbol was in a common package
	depth int,
	maxDepth int,
) {
	callStart := time.Now()
	defer func() {
		elapsed := time.Since(callStart)
		if elapsed > 500*time.Millisecond {
			log.Warn().Str("name", item.Name).Int("depth", depth).Dur("elapsed", elapsed).
				Msg("SLOW traceIncomingCalls")
		}
	}()

	log.Debug().Str("name", item.Name).Int("depth", depth).Msg("traceIncomingCalls")

	// Check depth limit
	if depth >= maxDepth {
		log.Warn().Str("name", item.Name).Int("depth", depth).Msg("Max trace depth reached, stopping recursion")
		return
	}

	// Create a unique key for this item
	key := fmt.Sprintf("%s:%d:%d", item.URI, item.Range.Start.Line, item.Range.Start.Character)

	if visited[key] {
		log.Debug().Str("key", key).Msg("Already visited")
		return
	}
	visited[key] = true

	// Check if this is a main function
	if isMainFunction(item) {
		binaryName := getBinaryName(item)

		// Check global cache first (thread-safe early exit using sync.Map)
		if _, alreadySeen := t.globalSeenBinaries.LoadOrStore(binaryName, true); alreadySeen {
			log.Debug().Str("binary", binaryName).Msg("Binary already found globally, skipping")
			return
		}

		// Deduplicate by binary name locally
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

	// Get incoming calls (with caching using sync.Map)
	cacheKey := fmt.Sprintf("%s:%d:%d", item.URI, item.Range.Start.Line, item.Range.Start.Character)

	var incomingCalls []protocol.CallHierarchyIncomingCall

	// Try cache first
	if cached, ok := t.callCache.Load(cacheKey); ok {
		log.Debug().Str("key", cacheKey).Msg("Using cached IncomingCalls")
		incomingCalls = cached.([]protocol.CallHierarchyIncomingCall)
	} else {
		// Get file handle for incoming calls
		fh, err := t.snapshot.ReadFile(t.ctx, item.URI)
		if err != nil {
			fmt.Printf("Warning: failed to read file %s: %v\n", item.URI, err)
			return
		}

		// Get incoming calls using gopls internal API
		// Add timing to measure how slow this is
		startTime := time.Now()
		incomingCalls, err = golang.IncomingCalls(t.ctx, t.snapshot, fh, item.Range.Start)
		elapsed := time.Since(startTime)
		if err != nil {
			fmt.Printf("Warning: failed to get incoming calls for %s: %v\n", item.Name, err)
			return
		}

		// Log slow calls
		if elapsed > 500*time.Millisecond {
			log.Warn().Str("name", item.Name).Dur("elapsed", elapsed).
				Msg("SLOW IncomingCalls detected")
		} else {
			log.Debug().Str("name", item.Name).Dur("elapsed", elapsed).
				Msg("IncomingCalls timing")
		}

		// Cache the result
		t.callCache.Store(cacheKey, incomingCalls)
		log.Debug().Str("key", cacheKey).Int("count", len(incomingCalls)).Msg("Cached IncomingCalls")
	}

	// Filter out test functions early (huge performance win)
	incomingCalls = filterTestFunctions(incomingCalls)

	pkgPath := extractPackageFromItem(item)

	if len(incomingCalls) == 0 {
		// Dead end - no callers found
		log.Debug().Str("name", item.Name).Str("package", pkgPath).Msg("No incoming calls found")
		return
	}

	// Limit the number of callers to avoid exponential explosion
	const maxCallersPerLevel = 20
	if len(incomingCalls) > maxCallersPerLevel {
		log.Debug().Str("name", item.Name).Int("original", len(incomingCalls)).
			Int("limited", maxCallersPerLevel).Msg("Limiting callers per level")
		incomingCalls = incomingCalls[:maxCallersPerLevel]
	}

	log.Debug().Str("name", item.Name).Int("count", len(incomingCalls)).Msg("IncomingCalls returned callers")
	for i, call := range incomingCalls {
		log.Debug().Int("index", i).Str("name", call.From.Name).
			Str("detail", call.From.Detail).Str("uri", string(call.From.URI)).Msg("Caller")
	}

	// CRITICAL: Filter out ambiguous interface calls
	// When gopls returns incoming calls for an interface method, it includes ALL
	// callers of that interface, not just the ones calling THIS specific implementation.
	// We need to filter these to avoid cross-service false positives.
	filterStart := time.Now()
	incomingCalls = t.filterAmbiguousInterfaceCalls(item, currentPath, incomingCalls, startedInCommonPkg)
	filterElapsed := time.Since(filterStart)
	if filterElapsed > 100*time.Millisecond {
		log.Warn().Str("name", item.Name).Dur("elapsed", filterElapsed).
			Int("callers", len(incomingCalls)).Msg("SLOW filtering detected")
	}

	// Recursively trace each caller
	for _, call := range incomingCalls {
		// Use URI-based package extraction for accurate results
		// (Detail can be incorrect for interface calls)
		callerPkg := t.extractPackageFromURI(call.From.URI)
		if callerPkg == "" {
			// Fallback to Detail-based extraction
			callerPkg = extractPackageFromItem(call.From)
		}

		callerNode := CallNode{
			FunctionName: call.From.Name,
			PackagePath:  callerPkg,
		}
		log.Debug().Str("name", call.From.Name).Str("package", callerPkg).
			Str("detail", call.From.Detail).Msg("Adding caller")

		// Build the new path with the caller
		newPath := append([]CallNode{callerNode}, currentPath...)

		t.traceIncomingCallsWithDepth(call.From, newPath, visited, paths, seenBinaries, startedInCommonPkg, depth+1, maxDepth)
	}
}

// traceIncomingCalls is kept for backward compatibility
func (t *DirectTracer) traceIncomingCalls(
	item protocol.CallHierarchyItem,
	currentPath []CallNode,
	visited map[string]bool,
	paths *[]CallPath,
	seenBinaries map[string]bool,
	startedInCommonPkg bool,
) {
	t.traceIncomingCallsWithDepth(item, currentPath, visited, paths, seenBinaries, startedInCommonPkg, 0, 50)
}

// isCrossServiceCall checks if a call path crosses service boundaries
// It detects invalid cross-service calls, especially for internal/ packages
func isCrossServiceCall(path []CallNode) bool {
	if len(path) < 2 {
		return false
	}

	// Collect all internal/ packages in the path
	internalServices := make(map[string]bool)
	for _, node := range path {
		if strings.Contains(node.PackagePath, "/internal/") {
			// Extract service name from "xxx/internal/service/..."
			internalIdx := strings.Index(node.PackagePath, "/internal/")
			if internalIdx >= 0 {
				remaining := node.PackagePath[internalIdx+len("/internal/"):]
				parts := strings.Split(remaining, "/")
				if len(parts) > 0 {
					internalServices[parts[0]] = true
				}
			}
		}
	}

	// If no internal package found, use the old cross-service detection logic
	if len(internalServices) == 0 {
		// Check for cross-service calls between different cmd/ services
		for i := 0; i < len(path)-1; i++ {
			service1 := extractServiceName(path[i].PackagePath)
			service2 := extractServiceName(path[i+1].PackagePath)

			if service1 != "" && service2 != "" && service1 != service2 {
				if !isCommonPackage(path[i].PackagePath) && !isCommonPackage(path[i+1].PackagePath) {
					return true
				}
			}
		}
		return false
	}

	// Internal packages found - check if path mixes different services
	// If we have internal/bill and internal/rfs in the same path, it's invalid
	if len(internalServices) > 1 {
		return true // Cross-service call detected
	}

	// Single internal service - check if path crosses service boundaries via common packages
	var singleInternalService string
	for svc := range internalServices {
		singleInternalService = svc
		break
	}

	// Path is built from caller to callee: [caller, ..., callee]
	// Example: [pkg/grace.main, internal/bill/server.Run, ..., api/manager/client.AdminListImage]
	//
	// We need to detect the pattern where:
	// - Path contains internal/service-A nodes
	// - Path also contains cmd/service-B or main package nodes (where service-B != service-A)
	// - They are connected through common packages like pkg/grace
	//
	// This detects: cmd/rfs/main -> pkg/grace.main -> internal/bill/... -> api/manager/client

	// Check each node in the path
	for _, node := range path {
		nodeService := extractServiceName(node.PackagePath)

		// If this node belongs to a cmd/ or has a service name
		if nodeService != "" && nodeService != singleInternalService {
			// Check if this is not a common package
			if !isCommonPackage(node.PackagePath) {
				// This is a different service's cmd/ or internal/ - cross-service call!
				return true
			}
		}
	}

	return false
}

// extractServiceName extracts the service name from a package path
// Package paths can be either relative (cmd/foo, internal/bar) or full (github.com/user/repo/cmd/foo)
func extractServiceName(pkgPath string) string {
	// Check for /cmd/ pattern (works for both relative and full paths)
	if strings.Contains(pkgPath, "/cmd/") {
		cmdIdx := strings.Index(pkgPath, "/cmd/")
		remaining := pkgPath[cmdIdx+len("/cmd/"):]
		parts := strings.Split(remaining, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Check for /internal/ pattern
	if strings.Contains(pkgPath, "/internal/") {
		internalIdx := strings.Index(pkgPath, "/internal/")
		remaining := pkgPath[internalIdx+len("/internal/"):]
		parts := strings.Split(remaining, "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// isCommonPackage checks if a package is a common/shared package
// Works with both relative and full package paths
func isCommonPackage(pkgPath string) bool {
	// Check if this is a truly shared package, not service-specific
	// Shared packages are those that don't have a service identifier in their path
	// For example:
	//   - github.com/qbox/las/pkg/grace -> shared (no service ID after /pkg/)
	//   - github.com/qbox/las/api/manager/client -> NOT shared (has /internal/ or service-specific sub-path)
	//   - example.com/project/pkg/common -> shared

	// First check if it contains common package patterns
	commonPatterns := []string{
		"/pkg/",
		"/common/",
		"/shared/",
		"/lib/",
	}

	hasCommonPattern := false
	for _, pattern := range commonPatterns {
		if strings.Contains(pkgPath, pattern) {
			hasCommonPattern = true
			break
		}
	}

	if !hasCommonPattern {
		return false
	}

	// Check that it doesn't contain service-specific indicators AFTER the common pattern
	// If there's an /internal/ or /cmd/ after /pkg/, it's service-specific
	afterPkg := ""
	if idx := strings.Index(pkgPath, "/pkg/"); idx >= 0 {
		afterPkg = pkgPath[idx+5:]
	} else if idx := strings.Index(pkgPath, "/common/"); idx >= 0 {
		afterPkg = pkgPath[idx+8:]
	} else if idx := strings.Index(pkgPath, "/shared/"); idx >= 0 {
		afterPkg = pkgPath[idx+8:]
	} else if idx := strings.Index(pkgPath, "/lib/"); idx >= 0 {
		afterPkg = pkgPath[idx+5:]
	}

	// If there's nothing after, or no service-specific marker, it's shared
	return !strings.Contains(afterPkg, "/internal/") && !strings.Contains(afterPkg, "/cmd/")
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

// Reference represents a reference to a symbol
type Reference struct {
	URI          string
	Range        protocol.Range
	ContainingFunc string // Name of the function containing this reference
}

// FindReferences finds all references to a symbol at the given position
func (t *DirectTracer) FindReferences(pos Position, symbolName string) ([]Reference, error) {
	// Convert file path to URI
	uri := protocol.URIFromPath(pos.Filename)

	// Get file handle from snapshot
	fh, err := t.snapshot.ReadFile(t.ctx, uri)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Convert position to protocol.Position (0-based)
	position := protocol.Position{
		Line:      uint32(pos.Line - 1),
		Character: uint32(pos.Column - 1),
	}

	// Call gopls internal References API
	locations, err := golang.References(t.ctx, t.snapshot, fh, position, true)
	if err != nil {
		return nil, fmt.Errorf("failed to find references: %w", err)
	}

	if len(locations) == 0 {
		return nil, nil
	}

	// Convert locations to references
	var refs []Reference
	for _, loc := range locations {
		ref := Reference{
			URI:   string(loc.URI),
			Range: loc.Range,
		}

		// Try to find the containing function for this reference
		containingFunc, err := t.findContainingFunction(loc.URI, loc.Range.Start)
		if err == nil {
			ref.ContainingFunc = containingFunc
		}

		refs = append(refs, ref)
	}

	return refs, nil
}

// findContainingFunction finds the function containing a given position
func (t *DirectTracer) findContainingFunction(uri protocol.DocumentURI, position protocol.Position) (string, error) {
	// Get file handle
	fh, err := t.snapshot.ReadFile(t.ctx, uri)
	if err != nil {
		return "", err
	}

	// Try PrepareCallHierarchy first (works if position is at function declaration)
	items, err := golang.PrepareCallHierarchy(t.ctx, t.snapshot, fh, position)
	if err == nil && len(items) > 0 {
		return items[0].Name, nil
	}

	// If PrepareCallHierarchy doesn't work, use AST to find the containing function
	// This works for any position inside a function body
	pgf, err := t.snapshot.ParseGo(t.ctx, fh, parsego.Full)
	if err != nil {
		return "", fmt.Errorf("failed to parse file: %w", err)
	}

	// Convert position to offset
	offset, err := pgf.Mapper.PositionOffset(position)
	if err != nil {
		return "", fmt.Errorf("failed to convert position to offset: %w", err)
	}

	// Find the enclosing function by walking the AST
	var foundFunc string
	ast.Inspect(pgf.File, func(n ast.Node) bool {
		if foundFunc != "" {
			return false
		}

		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}

		// Check if the offset is within this function
		if fn.Pos() <= pgf.Tok.Pos(offset) && pgf.Tok.Pos(offset) <= fn.End() {
			if fn.Name != nil {
				foundFunc = fn.Name.Name
				return false
			}
		}

		return true
	})

	if foundFunc != "" {
		return foundFunc, nil
	}

	return "", fmt.Errorf("no containing function found at %s:%d:%d", uri, position.Line, position.Character)
}

// findFunctionDeclaration finds the declaration position of a function by name
func (t *DirectTracer) findFunctionDeclaration(fh file.Handle, funcName string) (Position, error) {
	pgf, err := t.snapshot.ParseGo(t.ctx, fh, parsego.Full)
	if err != nil {
		return Position{}, err
	}

	var foundPos Position
	ast.Inspect(pgf.File, func(n ast.Node) bool {
		if foundPos.Filename != "" {
			return false
		}

		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != funcName {
			return true
		}

		// Found the function declaration
		pos := pgf.Tok.Position(fn.Name.Pos())
		foundPos = Position{
			Filename: pos.Filename,
			Line:     pos.Line,
			Column:   pos.Column,
		}
		return false
	})

	if foundPos.Filename != "" {
		return foundPos, nil
	}

	return Position{}, fmt.Errorf("function %s not found", funcName)
}

// TraceReferencesToMain traces all references of a symbol to main functions
func (t *DirectTracer) TraceReferencesToMain(pos Position, symbolName string) ([]CallPath, error) {
	// Find all references
	refs, err := t.FindReferences(pos, symbolName)
	if err != nil {
		return nil, fmt.Errorf("failed to find references: %w", err)
	}

	if len(refs) == 0 {
		return nil, nil
	}

	// For each reference, trace the containing function to main
	var allPaths []CallPath
	seenBinaries := make(map[string]bool)

	for _, ref := range refs {
		if ref.ContainingFunc == "" {
			continue
		}

		// Convert reference position back to Position
		// We use the reference position because PrepareCallHierarchy will find the function declaration
		refPos := Position{
			Filename: strings.TrimPrefix(ref.URI, "file://"),
			Line:     int(ref.Range.Start.Line) + 1,
			Column:   int(ref.Range.Start.Character) + 1,
		}

		// Get file handle
		uri := protocol.URIFromPath(refPos.Filename)
		fh, err := t.snapshot.ReadFile(t.ctx, uri)
		if err != nil {
			fmt.Printf("Warning: failed to read file %s: %v\n", refPos.Filename, err)
			continue
		}

		// Try to find the containing function declaration
		// Since we already have the function name from findContainingFunction,
		// we can search for it in the file
		funcPos, err := t.findFunctionDeclaration(fh, ref.ContainingFunc)
		if err != nil {
			// Fall back to using the reference position
			funcPos = refPos
		}

		// Trace this reference's containing function to main
		paths, err := t.TraceToMain(funcPos, ref.ContainingFunc)
		if err != nil {
			// Log but continue with other references
			fmt.Printf("Warning: failed to trace %s: %v\n", ref.ContainingFunc, err)
			continue
		}

		// Add paths, avoiding duplicates by binary name
		for _, path := range paths {
			if !seenBinaries[path.BinaryName] {
				seenBinaries[path.BinaryName] = true
				allPaths = append(allPaths, path)
			}
		}
	}

	return allPaths, nil
}

// FindMainPackagesImporting finds all main packages that import the target package (directly or indirectly)
// This is used for tracing init functions - when an init function changes, all main packages that import
// its package (even indirectly) are affected
func (t *DirectTracer) FindMainPackagesImporting(targetPkgPath string) ([]CallPath, error) {
	// Load the metadata graph to ensure all packages are loaded
	graph, err := t.snapshot.LoadMetadataGraph(t.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata graph: %w", err)
	}
	if graph == nil {
		return nil, fmt.Errorf("no metadata graph available")
	}

	var mainPackages []CallPath

	// Iterate through all packages to find main packages
	for _, meta := range graph.Packages {
		if meta.Name != "main" {
			continue
		}

		// Check if this main package imports the target package (directly or indirectly)
		if t.importsPackage(graph, meta, targetPkgPath) {
			// Extract binary name from the package path
			binaryName := extractBinaryNameFromPkgPath(string(meta.PkgPath))

			// Get the main URI
			mainURI := ""
			if len(meta.GoFiles) > 0 {
				mainURI = string(meta.GoFiles[0])
			}

			// Create a minimal call path - for init functions, there's no explicit call chain
			// The init function runs automatically when the package is imported
			mainPackages = append(mainPackages, CallPath{
				BinaryName: binaryName,
				MainURI:    mainURI,
				Path: []CallNode{
					{
						FunctionName: "main",
						PackagePath:  string(meta.PkgPath),
					},
				},
			})
		}
	}

	return mainPackages, nil
}

// importsPackage checks if a package imports the target package (directly or indirectly)
func (t *DirectTracer) importsPackage(graph *metadata.Graph, meta *metadata.Package, targetPkgPath string) bool {
	visited := make(map[metadata.PackageID]bool)
	return t.importsPackageRecursive(graph, meta, targetPkgPath, visited)
}

// importsPackageRecursive recursively checks package imports
func (t *DirectTracer) importsPackageRecursive(graph *metadata.Graph, meta *metadata.Package, targetPkgPath string, visited map[metadata.PackageID]bool) bool {
	// Already visited
	if visited[meta.ID] {
		return false
	}
	visited[meta.ID] = true

	pkgPath := string(meta.PkgPath)

	// Found it!
	if pkgPath == targetPkgPath {
		return true
	}

	// Check direct dependencies
	for depID := range meta.DepsByPkgPath {
		depPkgPath := string(depID)

		// Quick check: if this is the target, we found it
		if depPkgPath == targetPkgPath {
			return true
		}

		// Get metadata for this dependency from the graph
		for pid, depMeta := range graph.Packages {
			if string(depMeta.PkgPath) == depPkgPath {
				// Recursively check this dependency
				if t.importsPackageRecursive(graph, depMeta, targetPkgPath, visited) {
					return true
				}
				// Found the metadata for this dependency, no need to continue looping
				_ = pid
				break
			}
		}
	}

	return false
}

// extractBinaryNameFromPkgPath extracts binary name from package path
// Example: "example.com/init-test/cmd/server" -> "server"
func extractBinaryNameFromPkgPath(pkgPath string) string {
	parts := strings.Split(string(pkgPath), "/")

	// Look for "cmd" in the path
	for i, part := range parts {
		if part == "cmd" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	// Fallback: use last part
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return "unknown"
}

// filterAmbiguousInterfaceCalls filters out interface calls that would lead to cross-service false positives
// Core idea: Use the ACTUAL CALL PATH we've been tracing to filter out unrelated branches
// This completely avoids hardcoding any directory structures
func (t *DirectTracer) filterAmbiguousInterfaceCalls(
	currentItem protocol.CallHierarchyItem,
	currentPath []CallNode,
	incomingCalls []protocol.CallHierarchyIncomingCall,
	startedInCommonPkg bool,
) []protocol.CallHierarchyIncomingCall {
	// If we only have one caller, no ambiguity
	if len(incomingCalls) <= 1 {
		return incomingCalls
	}

	// Check if the CURRENT ITEM (the function being traced) is in a shared/common package
	// If so, don't filter - all callers are legitimate (multiple services can call shared functions)
	currentPkg := extractPackageFromItem(currentItem)
	if isCommonPackage(currentPkg) {
		log.Debug().Str("currentPkg", currentPkg).Msg("Current item is in shared package, no filtering needed")
		return incomingCalls
	}

	// Check call site diversity
	// Count unique caller packages
	// IMPORTANT: Use URI-based extraction for accurate package identification
	callerPackages := make(map[string]bool)
	for _, call := range incomingCalls {
		pkg := t.extractPackageFromURI(call.From.URI)
		if pkg == "" {
			pkg = extractPackageFromItem(call.From)
		}
		callerPackages[pkg] = true
	}

	log.Debug().Int("count", len(callerPackages)).Msg("Found unique caller packages")
	for pkg := range callerPackages {
		log.Debug().Str("package", pkg).Msg("Caller package")
	}

	// If all callers are from the same package, no ambiguity
	if len(callerPackages) <= 1 {
		log.Debug().Msg("Only one unique package, no filtering needed")
		return incomingCalls
	}

	// Core filtering logic: Score each caller by its relationship to the current path
	// The key insight: callers that share more package prefix with packages in currentPath
	// are more likely to be the correct call chain

	log.Debug().Str("currentItem", currentItem.Name).Int("pathLen", len(currentPath)).
		Msg("filterAmbiguousInterfaceCalls")
	for i, node := range currentPath {
		log.Debug().Int("index", i).Str("package", node.PackagePath).
			Str("function", node.FunctionName).Msg("currentPath node")
	}

	type scoredCall struct {
		call  protocol.CallHierarchyIncomingCall
		score int
	}

	var scoredCalls []scoredCall

	log.Debug().Str("currentPkg", currentPkg).Msg("Current package")

	for _, call := range incomingCalls {
		// Use URI-based extraction for accurate package identification
		callerPkg := t.extractPackageFromURI(call.From.URI)
		if callerPkg == "" {
			callerPkg = extractPackageFromItem(call.From)
		}
		score := 0

		// Score 1: How many packages in currentPath share prefix with this caller?
		for _, node := range currentPath {
			prefixLen := longestCommonPrefix(node.PackagePath, callerPkg)
			// Weight by prefix length - longer prefix = more related
			score += prefixLen / 10
		}

		// Score 2: Direct relationship to current package
		directPrefixLen := longestCommonPrefix(currentPkg, callerPkg)
		score += directPrefixLen / 5 // Higher weight for direct relationship

		// Score 3: Is this caller already in our path? (circular reference or related flow)
		for _, node := range currentPath {
			if node.PackagePath == callerPkg {
				score += 100 // Strong indicator of correct path
				break
			}
		}

		// Score 4: Check for service name consistency
		// Extract service identifiers from paths (e.g., "service-a", "service-b", "bill", "rfs")
		// If the path contains a specific service identifier and the caller also contains it,
		// give a bonus score
		// BUT: Only apply this if currentPath actually contains service-specific packages
		// (not just shared packages). This prevents over-filtering when tracing from shared packages.
		hasServiceSpecificPath := false
		for _, node := range currentPath {
			nodeServiceID := extractServiceIdentifier(node.PackagePath)
			if nodeServiceID != "" {
				hasServiceSpecificPath = true
				log.Debug().Str("package", node.PackagePath).Str("serviceID", nodeServiceID).
					Msg("Found service-specific path")
				break
			}
		}

		if hasServiceSpecificPath {
			callerServiceID := extractServiceIdentifier(callerPkg)
			if callerServiceID != "" {
				for _, node := range currentPath {
					nodeServiceID := extractServiceIdentifier(node.PackagePath)
					if nodeServiceID != "" && nodeServiceID == callerServiceID {
						score += 50 // Bonus for matching service identifier
						log.Debug().Str("callerID", callerServiceID).Str("nodeID", nodeServiceID).
							Msg("Service ID match bonus")
					}
				}
			}
		} else {
			log.Debug().Msg("No service-specific path, skipping service ID bonus")
		}

		log.Debug().Str("name", call.From.Name).Str("package", callerPkg).Int("score", score).
			Msg("Caller scored")
		scoredCalls = append(scoredCalls, scoredCall{call: call, score: score})
	}

	// Find the best score
	bestScore := -1
	for _, sc := range scoredCalls {
		if sc.score > bestScore {
			bestScore = sc.score
		}
	}

	// Critical threshold: Filter out callers with significantly lower scores
	// This indicates they're likely from a different call tree (interface ambiguity)
	const SCORE_THRESHOLD_RATIO = 0.5 // Keep callers within 50% of best score

	filtered := make([]protocol.CallHierarchyIncomingCall, 0, len(incomingCalls))
	for _, sc := range scoredCalls {
		// Keep if score is close to the best score
		if bestScore == 0 || sc.score >= int(float64(bestScore)*SCORE_THRESHOLD_RATIO) {
			filtered = append(filtered, sc.call)
		}
	}

	// Safety: If we filtered out everything, return all (conservative)
	if len(filtered) == 0 {
		return incomingCalls
	}

	return filtered
}

// longestCommonPrefix returns the length of the longest common prefix between two strings
func longestCommonPrefix(s1, s2 string) int {
	minLen := len(s1)
	if len(s2) < minLen {
		minLen = len(s2)
	}

	for i := 0; i < minLen; i++ {
		if s1[i] != s2[i] {
			return i
		}
	}

	return minLen
}

// filterTestFunctions filters out test functions and test files
// Test functions don't contribute to production call chains
func filterTestFunctions(calls []protocol.CallHierarchyIncomingCall) []protocol.CallHierarchyIncomingCall {
	var filtered []protocol.CallHierarchyIncomingCall
	for _, call := range calls {
		// Skip test files
		uri := string(call.From.URI)
		if strings.HasSuffix(uri, "_test.go") {
			continue
		}

		// Skip test functions (Test*, Benchmark*, Example*)
		funcName := call.From.Name
		if strings.HasPrefix(funcName, "Test") ||
			strings.HasPrefix(funcName, "Benchmark") ||
			strings.HasPrefix(funcName, "Example") {
			continue
		}

		filtered = append(filtered, call)
	}
	return filtered
}
