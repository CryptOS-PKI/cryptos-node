package etcd

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
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap/zapcore"
)

func TestOpen_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	srv, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	defer func() { _ = cli.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cli.Put(ctx, KeyStatePhase, "no-identity"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	resp, err := cli.Get(ctx, KeyStatePhase)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(resp.Kvs) != 1 {
		t.Fatalf("Get: got %d kvs, want 1", len(resp.Kvs))
	}
	if got, want := string(resp.Kvs[0].Value), "no-identity"; got != want {
		t.Fatalf("Get returned %q, want %q", got, want)
	}
}

func TestSchemaConstants_AreUnique(t *testing.T) {
	keys := []string{
		KeyRootCert,
		KeyRootKeyBlob,
		KeyRootKeyPublic,
		KeyStatePhase,
		KeyBootCount,
		PrefixCeremonyManifests,
		PrefixAuditLog,
		PrefixAdmins,
	}
	seen := map[string]struct{}{}
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			t.Fatalf("duplicate key in schema: %q", k)
		}
		seen[k] = struct{}{}
	}
	// Sanity: all keys live under /cryptos/.
	for _, k := range keys {
		if !strings.HasPrefix(k, "/cryptos/") {
			t.Fatalf("key %q not under /cryptos/", k)
		}
	}
}

func TestOpen_MissingDataDir(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatalf("Open(\"\") should have failed")
	}
}

func TestOpen_ClientFailsAfterClose(t *testing.T) {
	srv, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := srv.Client(); err == nil {
		t.Fatalf("Client() on closed Server should fail")
	}
}

func TestOpen_RangeOverPrefix(t *testing.T) {
	srv, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	defer func() { _ = cli.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	want := map[string]string{
		PrefixAuditLog + "0000000001": "entry-1",
		PrefixAuditLog + "0000000002": "entry-2",
		PrefixAuditLog + "0000000003": "entry-3",
	}
	for k, v := range want {
		if _, err := cli.Put(ctx, k, v); err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
	}

	// Range over the audit-log prefix and confirm we get back all three.
	resp, err := cli.Get(ctx, PrefixAuditLog, clientv3.WithPrefix())
	if err != nil {
		t.Fatalf("Get prefix: %v", err)
	}
	got := map[string]string{}
	for _, kv := range resp.Kvs {
		got[string(kv.Key)] = string(kv.Value)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefix range mismatch: got=%v want=%v", got, want)
	}
}

// PID 1 owns the console, so the client must not write its retry warnings to
// it. When init exits on a failed boot stage the client's calls are cancelled
// and it retries in a tight loop, and warnings from that loop would scroll the
// failed stage and its cause off the screen. Errors still get through.
func TestClient_LogsOnlyErrors(t *testing.T) {
	srv, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	cli, err := srv.Client()
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	defer func() { _ = cli.Close() }()

	core := cli.GetLogger().Core()
	if core.Enabled(zapcore.WarnLevel) {
		t.Fatalf("the client logs warnings; its retry warnings would flood the console")
	}
	if !core.Enabled(zapcore.ErrorLevel) {
		t.Fatalf("the client drops errors; a real client failure would go unreported")
	}
}
