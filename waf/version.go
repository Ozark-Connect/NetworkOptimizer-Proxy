package main

import (
	_ "embed"
	"runtime/debug"
	"strings"
)

// VERSION is bumped for each release; the release workflow refuses a tag that does not match it,
// so a source build reports the same version as the release it came from.
//
//go:embed VERSION
var versionFile string

// Version is the netopt-waf release this binary was built from.
var Version = strings.TrimSpace(versionFile)

// CRSVersion is the OWASP CRS release compiled in, read from the module the rules ship in.
var CRSVersion = crsVersion()

func crsVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/corazawaf/coraza-coreruleset/v4" {
			return strings.TrimPrefix(d.Version, "v")
		}
	}
	return ""
}
