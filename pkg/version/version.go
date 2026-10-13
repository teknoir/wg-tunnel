// Package version holds the build version, set with
//
//	-ldflags "-X github.com/teknoir/wg-tunnel/pkg/version.Version=v1.2.3"
package version

// Version is the build version; "dev" for untagged local builds.
var Version = "dev"
