//go:build tools

package tools

import (
	_ "github.com/ferranbt/fastssz/sszgen"
	_ "github.com/kisielk/errcheck"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
