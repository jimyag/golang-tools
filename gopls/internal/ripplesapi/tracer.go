// Package ripplesapi provides a public API to access gopls internal functionality
// for the ripples project
package ripplesapi

import (
	"context"
	"fmt"
	"go/ast"
	"path/filepath"
	"strings"

	"golang.org/x/tools/gopls/internal/cache"
	"golang.org/x/tools/gopls/internal/cache/metadata"
	"golang.org/x/tools/gopls/internal/cache/parsego"
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
		// Check if the initial symbol is in a common package
		startedInCommonPkg := isCommonPackage(initialNode.PackagePath)
		t.traceIncomingCalls(item, []CallNode{initialNode}, visited, &paths, seenBinaries, startedInCommonPkg)
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
	startedInCommonPkg bool, // true if the original changed symbol was in a common package
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

	pkgPath := extractPackageFromItem(item)

	if len(incomingCalls) == 0 {
		// Dead end - no callers found
		fmt.Printf("Debug: No incoming calls found for %s (package: %s)\n", item.Name, pkgPath)
		return
	}

	// CRITICAL: Filter out ambiguous interface calls
	// When gopls returns incoming calls for an interface method, it includes ALL
	// callers of that interface, not just the ones calling THIS specific implementation.
	// We need to filter these to avoid cross-service false positives.
	incomingCalls = t.filterAmbiguousInterfaceCalls(item, currentPath, incomingCalls, startedInCommonPkg)

	// Handle common package tracing logic
	currentIsCommon := isCommonPackage(pkgPath)

	if currentIsCommon {
		if !startedInCommonPkg {
			// We're tracing from internal/service and hit a common package - stop here
			// Continuing would cause false positives due to interface calls
			return
		}
		// If we started in a common package, we allow continuing through the same package
		// But stop if we reach a DIFFERENT common package (to prevent cross-package tracing)
		// Check: are we still in the original package or have we entered a different one?
		if len(currentPath) > 0 {
			originalPkg := currentPath[len(currentPath)-1].PackagePath // The first/original node
			if isCommonPackage(originalPkg) && originalPkg != pkgPath {
				// We've left the original common package and entered a different common package
				return
			}
		}
	}

	// Recursively trace each caller
	for _, call := range incomingCalls {
		callerNode := CallNode{
			FunctionName: call.From.Name,
			PackagePath:  extractPackageFromItem(call.From),
		}

		// Check if the caller is in a common package
		callerIsCommon := isCommonPackage(callerNode.PackagePath)

		// Case 1: Started from internal/ and reached a common package - stop
		if callerIsCommon && !startedInCommonPkg {
			continue
		}

		// Build the new path with the caller
		newPath := append([]CallNode{callerNode}, currentPath...)

		// Case 2: Started from common, went through internal, now back to common - stop
		// This prevents: api/manager -> internal/bill -> pkg/grace -> cmd/rfs (wrong!)
		// Pattern: common (changed) -> ... -> internal/service-A -> ... -> common (caller)
		if callerIsCommon && startedInCommonPkg {
			// Check if the path contains any internal/ package
			hasInternal := false
			for _, node := range currentPath {
				if strings.Contains(node.PackagePath, "/internal/") {
					hasInternal = true
					break
				}
			}
			// If we have: common (start) -> internal -> common (caller), stop here
			if hasInternal {
				continue
			}
		}

		// Case 3: Check if this path crosses service boundaries
		// This handles direct service-to-service calls
		if isCrossServiceCall(newPath) {
			continue
		}

		t.traceIncomingCalls(call.From, newPath, visited, paths, seenBinaries, startedInCommonPkg)
	}
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
	commonPatterns := []string{
		"/pkg/",
		"/api/",
		"/common/",
		"/shared/",
		"/lib/",
	}

	for _, pattern := range commonPatterns {
		if strings.Contains(pkgPath, pattern) {
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

	// Heuristic 1: Check if current item is a method that might implement an interface
	// Methods are more likely to be interface implementations
	isLikelyInterfaceMethod := strings.Contains(currentItem.Name, ".") ||
		(currentItem.Kind == protocol.Method)

	if !isLikelyInterfaceMethod {
		// Not an interface method, no filtering needed
		return incomingCalls
	}

	// Heuristic 2: Check call site diversity
	// Count unique caller packages
	callerPackages := make(map[string]bool)
	for _, call := range incomingCalls {
		pkg := extractPackageFromItem(call.From)
		callerPackages[pkg] = true
	}

	// If all callers are from the same package, no ambiguity
	if len(callerPackages) <= 1 {
		return incomingCalls
	}

	// Core filtering logic: Score each caller by its relationship to the current path
	// The key insight: callers that share more package prefix with packages in currentPath
	// are more likely to be the correct call chain

	type scoredCall struct {
		call  protocol.CallHierarchyIncomingCall
		score int
	}

	var scoredCalls []scoredCall

	currentPkg := extractPackageFromItem(currentItem)

	for _, call := range incomingCalls {
		callerPkg := extractPackageFromItem(call.From)
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
