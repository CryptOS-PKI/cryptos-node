//go:build !linux

package init

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

import "errors"

// LocateBootUKI is Linux-only; CryptOS only ever boots on Linux. This stub
// keeps the package buildable on a developer workstation.
func LocateBootUKI(string) (string, error) {
	return "", errors.New("init: LocateBootUKI: boot-media location is linux-only")
}
