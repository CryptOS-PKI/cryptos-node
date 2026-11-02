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
	"testing"
)

func TestGuestShutdown_MapsModesToActions(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want ShutdownAction
	}{
		{"powerdown", ShutdownPowerOff},
		{"halt", ShutdownPowerOff},
		{"reboot", ShutdownReboot},
	} {
		var got []ShutdownAction
		if err := guestShutdown(func(a ShutdownAction) { got = append(got, a) })(tc.mode); err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: requested %v, want [%v]", tc.mode, got, tc.want)
		}
	}
}

func TestGuestShutdown_RefusesAnUnknownMode(t *testing.T) {
	called := false
	if err := guestShutdown(func(ShutdownAction) { called = true })("suspend"); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
	if called {
		t.Fatal("an unknown mode requested a shutdown")
	}
}

// Maintenance parks on its own select; a guest agent request taken there must
// still decide what PID 1 does next.
func TestShutdownRequests_TakeRecordsTheAction(t *testing.T) {
	sd := newShutdownRequests()
	sd.Request(ShutdownPowerOff)
	select {
	case a := <-sd.Requested():
		sd.take(a)
	default:
		t.Fatal("the request was not delivered")
	}
	if got := sd.Action(); got != ShutdownPowerOff {
		t.Fatalf("Action = %v, want %v", got, ShutdownPowerOff)
	}
}
