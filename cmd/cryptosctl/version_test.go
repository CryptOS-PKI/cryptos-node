package main

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
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	gobuildinfo "github.com/Bugs5382/go-buildinfo"

	"github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"
)

// stampBuild sets the stamped build identity for one test, where the build
// stamps it: the version and commit in go-buildinfo, the build date in
// internal/buildinfo.
func stampBuild(t *testing.T, version, commit, date string) {
	t.Helper()
	old := [3]string{gobuildinfo.Version, gobuildinfo.Commit, buildinfo.BuildDate}
	t.Cleanup(func() { gobuildinfo.Version, gobuildinfo.Commit, buildinfo.BuildDate = old[0], old[1], old[2] })
	gobuildinfo.Version, gobuildinfo.Commit, buildinfo.BuildDate = version, commit, date
}

func TestVersion_ClientOnlyWithoutNode(t *testing.T) {
	stampBuild(t, "v1.2.3-4-gabcdef0", "abcdef0123456789", "2026-09-25T10:00:00Z")
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version: %v (out=%s)", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"v1.2.3-4-gabcdef0", "abcdef0123456789", "2026-09-25T10:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q:\n%s", want, out)
		}
	}
	// No --endpoint/--socket: the command must not dial the default endpoint.
	if strings.Contains(out, "Node") {
		t.Errorf("version without a node target printed node info:\n%s", out)
	}
}

func TestRoundTrip_VersionReportsNode(t *testing.T) {
	stampBuild(t, "v1.2.3", "abcdef0123456789", "2026-09-25T10:00:00Z")
	ts := startTestServer(t)
	out, err := ts.run(t, "version")
	if err != nil {
		t.Fatalf("version: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "v1.2.3") {
		t.Errorf("version output missing the client version:\n%s", out)
	}
	if !strings.Contains(out, "Node version:") || !strings.Contains(out, "test") {
		t.Errorf("version output missing the node version:\n%s", out)
	}
}

func TestRoundTrip_VersionJSON(t *testing.T) {
	stampBuild(t, "v1.2.3", "abcdef0123456789", "2026-09-25T10:00:00Z")
	ts := startTestServer(t)
	out, err := ts.run(t, "version", "-o", "json")
	if err != nil {
		t.Fatalf("version -o json: %v (out=%s)", err, out)
	}
	var got versionReport
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if got.Client.Version != "v1.2.3" || got.Client.Commit != "abcdef0123456789" {
		t.Errorf("client = %+v", got.Client)
	}
	if got.Node == nil || got.Node.Version != "test" {
		t.Errorf("node = %+v, want version test", got.Node)
	}
}

// TestVersion_OutputIsStable pins the exact `cryptosctl version` output in
// every format, so a change to how the build identity is stamped never
// changes what scripts and operators read.
func TestVersion_OutputIsStable(t *testing.T) {
	stampBuild(t, "v1.2.3-4-gabcdef0", "abcdef0123456789", "2026-09-25T10:00:00Z")
	gv := runtime.Version()
	tests := []struct {
		format string
		want   string
	}{
		{"human", "Client version:  v1.2.3-4-gabcdef0\n" +
			"Client commit:   abcdef0123456789\n" +
			"Client built:    2026-09-25T10:00:00Z\n" +
			"Go version:      " + gv + "\n"},
		{"json", "{\n" +
			"  \"client\": {\n" +
			"    \"version\": \"v1.2.3-4-gabcdef0\",\n" +
			"    \"commit\": \"abcdef0123456789\",\n" +
			"    \"build_date\": \"2026-09-25T10:00:00Z\",\n" +
			"    \"go_version\": \"" + gv + "\"\n" +
			"  }\n" +
			"}\n"},
		{"yaml", "client:\n" +
			"    build_date: \"2026-09-25T10:00:00Z\"\n" +
			"    commit: abcdef0123456789\n" +
			"    go_version: " + gv + "\n" +
			"    version: v1.2.3-4-gabcdef0\n"},
	}
	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			root := newRootCmd()
			var buf bytes.Buffer
			root.SetOut(&buf)
			root.SetErr(&buf)
			root.SetArgs([]string{"version", "-o", tc.format})
			if err := root.Execute(); err != nil {
				t.Fatalf("version -o %s: %v (out=%s)", tc.format, err, buf.String())
			}
			if got := buf.String(); got != tc.want {
				t.Errorf("version -o %s =\n%q\nwant\n%q", tc.format, got, tc.want)
			}
		})
	}
}
