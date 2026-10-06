// Package buildinfo carries the build identity of every CryptOS binary: the
// version, the commit it was built from, and when.
//
// The values are stamped at build time with -ldflags -X by
// scripts/buildinfo.sh, which `task build` uses for every binary in this
// checkout, so they report the same identity:
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

import "runtime/debug"

const (
	devVersion = "dev"
	unknown    = "unknown"
)

// Stamped at build time via -ldflags -X; see the package comment.
var (
	// Version is `git describe --tags --always --dirty` of the build tree.
	Version = devVersion
	// Commit is the full commit hash, suffixed -dirty for a modified tree.
	Commit = ""
	// BuildDate is the RFC 3339 UTC time of the commit the build came from.
	BuildDate = ""
)

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
	return resolve(Version, Commit, BuildDate, bi)
}

// resolve prefers the stamped values and fills anything left unstamped from
// the toolchain's VCS metadata, then from "unknown".
func resolve(version, commit, date string, bi *debug.BuildInfo) Info {
	if commit == "" || date == "" {
		rev, when, dirty := vcs(bi)
		if commit == "" && rev != "" {
			commit = rev
			if dirty {
				commit += "-dirty"
			}
		}
		if date == "" {
			date = when
		}
	}
	if version == "" {
		version = devVersion
	}
	if commit == "" {
		commit = unknown
	}
	if date == "" {
		date = unknown
	}
	return Info{Version: version, Commit: commit, BuildDate: date}
}

// vcs extracts the revision, commit time, and modified flag the Go toolchain
// records for a build made inside a VCS checkout.
func vcs(bi *debug.BuildInfo) (rev, when string, dirty bool) {
	if bi == nil {
		return "", "", false
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			when = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return rev, when, dirty
}
