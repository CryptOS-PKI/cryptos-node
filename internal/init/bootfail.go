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

import (
	"log"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// bootFailHold is how long the node holds a failed boot stage on the console
// before it restarts. The kernel command line has panic=1, so without a hold a
// failing node restarts within a second and the reason it failed is never on
// the screen long enough to read. Thirty seconds is enough for a few lines on a
// VM console and short enough that a boot loop stays a loop a person can
// interrupt.
const bootFailHold = 30 * time.Second

// reportBootFailure shows why a boot stage failed and holds the screen before
// the node restarts. It draws the stage and its cause on the console, logs the
// same, then calls sleep(bootFailHold). It does nothing visible, and does not
// hold, when no stage was running (nothing was drawn for it) or when there is
// no console: there is then nothing to read, so the node restarts as before.
func reportBootFailure(scr *console.Renderer, step string, cause error, sleep func(time.Duration)) {
	if cause != nil {
		log.Printf("init: boot failed at stage %q: %v", step, cause)
	}
	if scr == nil || step == "" {
		return
	}
	if err := scr.StepFailed(step, cause); err != nil {
		return
	}
	sleep(bootFailHold)
}
