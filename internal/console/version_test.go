package console_test

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
	"strings"
	"testing"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// The build stamps a git-describe version, which already starts with "v".
func TestFooterVersion(t *testing.T) {
	for _, tc := range []struct{ version, want string }{
		{"v0.1.0", "v0.1.0"},
		{"v0.1.0-3-gabc1234", "v0.1.0-3-gabc1234"},
		{"0.1.0", "v0.1.0"},
		{"dev", "dev"},
		{"", "v?"},
	} {
		v := console.View{RootCN: "Example Root CA G1", Role: "ROOT", NodeStatus: "ESTABLISHED", TPM: "SEALED", Version: tc.version}
		lines := screenLines(console.RenderDashboard(v, 80, 25))
		footer := strings.Trim(lines[len(lines)-2], "| ")
		if !strings.HasSuffix(footer, " "+tc.want) {
			t.Errorf("version %q: footer = %q, want it to end in %q", tc.version, footer, tc.want)
		}
	}
}
