package grpc

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
	"os"
	"path/filepath"
	"testing"
)

// shortSockPath returns a path for a Unix socket in a short directory. A Unix
// socket path is limited to 104 bytes on macOS (108 on Linux), and a test's own
// temp directory under macOS's $TMPDIR is already longer than that, so binding a
// socket in t.TempDir() fails there with "invalid argument". /tmp is short on
// both; if it can't be used the test's own temp directory is the fallback.
func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cs-")
	if err != nil {
		return filepath.Join(t.TempDir(), "cryptos.sock")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "cryptos.sock")
}
