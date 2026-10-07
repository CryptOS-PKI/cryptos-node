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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// A failed snapshot has no node version; the console fills in its own so the
// degraded footer is never "v?". A version the node reports wins.
func TestWithVersionFillsAMissingVersion(t *testing.T) {
	failed := func(context.Context) (console.View, error) {
		return console.View{Degraded: true}, errors.New("dial failed")
	}
	v, err := withVersion(failed, "v0.1.0")(context.Background())
	if err == nil || v.Version != "v0.1.0" {
		t.Fatalf("failed snapshot: version %q, err %v; want v0.1.0 and the error kept", v.Version, err)
	}
	reported := func(context.Context) (console.View, error) {
		return console.View{Version: "v0.2.0"}, nil
	}
	if v, _ := withVersion(reported, "v0.1.0")(context.Background()); v.Version != "v0.2.0" {
		t.Fatalf("reported version replaced: %q", v.Version)
	}
}

// The degraded frame drawn before the socket answers shows the version.
func TestRenderDegradedShowsTheVersion(t *testing.T) {
	var buf bytes.Buffer
	renderDegraded(&buf, "v0.1.0", 80, 24)
	if out := buf.String(); !strings.Contains(out, "v0.1.0") || strings.Contains(out, "v?") {
		t.Fatalf("degraded footer has no version:\n%s", out)
	}
}
