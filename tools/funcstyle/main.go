package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

func main() {
	fix := flag.Bool("fix", false, "rewrite the reported functions instead of failing")
	exclude := flag.String("exclude", "", "regular expression of slash-separated paths to skip")

	flag.Parse()

	var skip *regexp.Regexp

	if *exclude != "" {
		var err error

		skip, err = regexp.Compile(*exclude)
		if err != nil {
			fmt.Fprintf(os.Stderr, "funcstyle: -exclude: %v\n", err)
			os.Exit(2)
		}
	}

	roots := flag.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	found := 0

	for _, root := range roots {
		n, err := walk(root, skip, *fix)
		if err != nil {
			fmt.Fprintf(os.Stderr, "funcstyle: %v\n", err)
			os.Exit(2)
		}

		found += n
	}

	if found > 0 && !*fix {
		fmt.Fprintf(os.Stderr, "funcstyle: %d function(s) with a one-line body; run with -fix (make fmt)\n", found)
		os.Exit(1)
	}
}

func walk(root string, skip *regexp.Regexp, fix bool) (int, error) {
	found := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		slashed := filepath.ToSlash(path)

		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || slices.Contains([]string{"bin", "node_modules", "vendor", "testdata"}, name)) {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || (skip != nil && skip.MatchString(slashed)) {
			return nil
		}

		n, err := check(path, fix)
		found += n

		return err
	})

	return found, err
}

func check(path string, fix bool) (int, error) {
	src, err := os.ReadFile(path) //nolint:gosec // the paths are the source files of the walked tree
	if err != nil {
		return 0, err
	}

	fset := token.NewFileSet()

	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return 0, err
	}

	if ast.IsGenerated(file) {
		return 0, nil
	}

	found := 0
	var breaks []int

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || len(fn.Body.List) == 0 {
			continue
		}

		open, closing := fset.Position(fn.Body.Lbrace), fset.Position(fn.Body.Rbrace)
		if open.Line != closing.Line {
			continue
		}

		if !fix {
			fmt.Printf("%s:%d: %s: the body of a function goes on its own lines\n", filepath.ToSlash(path), open.Line, name(fn))
		}

		found++

		breaks = append(breaks, open.Offset+1, closing.Offset)

		if end := closing.Offset + 1; end+1 < len(src) && src[end] == '\n' && src[end+1] != '\n' {
			breaks = append(breaks, end)
		}
	}

	if !fix || found == 0 {
		return found, nil
	}

	var out bytes.Buffer

	last := 0
	for _, at := range breaks {
		out.Write(src[last:at])
		out.WriteByte('\n')

		last = at
	}

	out.Write(src[last:])

	formatted, err := format.Source(out.Bytes())
	if err != nil {
		return 0, errors.Join(fmt.Errorf("format %s after the fix", path), err)
	}

	return found, os.WriteFile(path, formatted, 0o644) //nolint:gosec // a source file keeps the usual mode
}

func name(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}

	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}

	if index, ok := recv.(*ast.IndexExpr); ok {
		recv = index.X
	}

	if ident, ok := recv.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}

	return fn.Name.Name
}
