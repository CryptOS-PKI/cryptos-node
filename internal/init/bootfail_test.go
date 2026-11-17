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
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CryptOS-PKI/cryptos-node/internal/console"
)

// A node that stops on a failed boot stage restarts at once (panic=1 on the
// kernel command line) with no shell, so the console is the only place the
// reason can be read. The failure is drawn under the stage, and the node holds
// so a person can read it before the restart.
func TestReportBootFailure_DrawsTheCauseThenHolds(t *testing.T) {
	var buf bytes.Buffer
	var held []time.Duration
	cause := errors.New("init: ServerTLSConfig: the mTLS listener needs the full bootstrap admin certificate (PEM), not just a fingerprint")

	reportBootFailure(console.NewRenderer(&buf), "management API", cause, func(d time.Duration) { held = append(held, d) })

	out := buf.String()
	if !strings.Contains(out, "[!!]  management API\n") {
		t.Fatalf("the failed stage line was not drawn:\n%s", out)
	}
	if got := strings.Join(strings.Fields(out), " "); !strings.Contains(got, cause.Error()) {
		t.Fatalf("the cause was not drawn under the stage:\n%s", out)
	}
	if len(held) != 1 || held[0] != bootFailHold {
		t.Fatalf("held %v, want exactly one hold of %v", held, bootFailHold)
	}
}

// The hold is 30 seconds: long enough to read a few lines on a VM console, and
// short enough that a boot loop stays a loop a person can interrupt.
func TestBootFailHoldIsThirtySeconds(t *testing.T) {
	if bootFailHold != 30*time.Second {
		t.Fatalf("bootFailHold = %v, want 30s", bootFailHold)
	}
}

// A failure before any stage began (an early mount, say) draws nothing, so
// there is nothing to read and the node must not sit still for 30 seconds.
func TestReportBootFailure_NoStageDrawsAndHoldsNothing(t *testing.T) {
	var buf bytes.Buffer
	held := 0
	reportBootFailure(console.NewRenderer(&buf), "", errors.New("mount: boom"), func(time.Duration) { held++ })
	if buf.Len() != 0 {
		t.Fatalf("drew %q with no stage running", buf.String())
	}
	if held != 0 {
		t.Fatalf("held %d times with nothing drawn", held)
	}
}

// With no console (it could not be opened) there is nothing to draw on, so the
// node restarts without waiting, as before.
func TestReportBootFailure_NoConsoleHoldsNothing(t *testing.T) {
	held := 0
	reportBootFailure(nil, "network", errors.New("link: boom"), func(time.Duration) { held++ })
	if held != 0 {
		t.Fatalf("held %d times with no console", held)
	}
}
