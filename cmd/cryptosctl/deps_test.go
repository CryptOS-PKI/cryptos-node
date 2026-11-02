package main

/*
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
	"os/exec"
	"strings"
	"testing"
)

// TestCLIDoesNotLinkTheTPMPackage keeps the operator CLI buildable on every
// workstation OS. internal/tpm pulls in a Linux-only transport, so one import
// of it from the CLI's graph breaks the Windows build.
func TestCLIDoesNotLinkTheTPMPackage(t *testing.T) {
	const tpmPkg = "github.com/CryptOS-PKI/cryptos-node/internal/tpm"
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-e", "-deps", ".")
			cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list: %v", err)
			}
			for _, pkg := range strings.Fields(string(out)) {
				if pkg == tpmPkg {
					t.Fatalf("cryptosctl on %s links %s", goos, tpmPkg)
				}
			}
		})
	}
}
