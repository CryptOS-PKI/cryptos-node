// Package buildinfo carries the build identity of every CryptOS binary: the
// version, the commit it was built from, and when.
//
// The version and commit are github.com/Bugs5382/go-buildinfo's, stamped
// there with -ldflags -X; the build date, which go-buildinfo doesn't carry,
// is stamped here. scripts/buildinfo.sh prints all three flags, and
// `task build` uses it for every binary in this checkout, so they report the
// same identity:
//
//	go build -ldflags "$(scripts/buildinfo.sh)" ./cmd/cryptosctl
//
// An unstamped build still identifies itself as well as it can: the commit and
// build date fall back to the VCS metadata the Go toolchain embeds when it
// builds inside a git checkout, and the version stays "dev".
package buildinfo

/*
Copyright The CryptOS Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"runtime/debug"

	gobuildinfo "github.com/Bugs5382/go-buildinfo"
)

const unknown = "unknown"

// BuildDate is the RFC 3339 UTC time of the commit the build came from,
// stamped at build time via -ldflags -X; see the package comment.
var BuildDate = ""

// Info is a resolved build identity.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

// Get returns the build identity of the running binary.
func Get() Info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		bi = nil
	}
	return resolve(gobuildinfo.Get(), gobuildinfo.Commit != "", BuildDate, bi)
}

// resolve combines go-buildinfo's version and commit with the build date.
// go-buildinfo already falls back to the VCS revision and then "unknown" for
// an unstamped commit; a revision taken from a modified tree is suffixed
// -dirty here, as a stamped commit from a modified tree is. An unstamped date
// falls back to the VCS commit time, then "unknown".
func resolve(g gobuildinfo.Info, commitStamped bool, date string, bi *debug.BuildInfo) Info {
	commit := g.Commit
	if !commitStamped && g.Modified && commit != unknown {
		commit += "-dirty"
	}
	if date == "" {
		date = vcsTime(bi)
	}
	if date == "" {
		date = unknown
	}
	return Info{Version: g.Version, Commit: commit, BuildDate: date}
}

// vcsTime returns the commit time the Go toolchain records for a build made
// inside a VCS checkout.
func vcsTime(bi *debug.BuildInfo) string {
	if bi == nil {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.time" {
			return s.Value
		}
	}
	return ""
}
