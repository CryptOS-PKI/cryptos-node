package tsa

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
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

var gateNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// goodSync is a time-sync status whose last good sync was age ago and
// measured offset. state is what the latest round left behind.
func goodSync(state nodev1.TimeSyncState, offset, age time.Duration) *nodev1.TimeSyncStatus {
	return &nodev1.TimeSyncStatus{
		State:      state,
		LastOffset: durationpb.New(offset),
		LastSync:   timestamppb.New(gateNow.Add(-age)),
	}
}

func TestClockGate(t *testing.T) {
	const synced = nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED
	const unsynced = nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED
	limits := ClockLimits{MaxSyncAge: time.Hour, MaxDriftPPM: 100, MaxClockError: time.Second}
	// At 100 ppm an hour of drift is 360ms, so offset 640ms at exactly
	// MaxSyncAge lands exactly on MaxClockError.
	for name, tc := range map[string]struct {
		status *nodev1.TimeSyncStatus
		limits ClockLimits
		limit  string // empty means the gate passes
	}{
		"fresh good sync": {status: goodSync(synced, 20*time.Millisecond, 0)},
		"one failed poll within the window": {status: func() *nodev1.TimeSyncStatus {
			st := goodSync(unsynced, 20*time.Millisecond, 2*time.Minute)
			st.LastError = "192.0.2.1: i/o timeout"
			return st
		}()},
		"age exactly max_sync_age":   {status: goodSync(unsynced, 0, time.Hour)},
		"age past max_sync_age":      {status: goodSync(unsynced, 0, time.Hour+time.Nanosecond), limit: LimitMaxSyncAge},
		"age far past max_sync_age":  {status: goodSync(synced, 0, 3*time.Hour), limit: LimitMaxSyncAge},
		"error exactly the bound":    {status: goodSync(unsynced, 640*time.Millisecond, time.Hour)},
		"error grows past the bound": {status: goodSync(unsynced, 641*time.Millisecond, time.Hour), limit: LimitMaxClockError},
		"error crosses the bound mid-window": {
			status: goodSync(unsynced, 900*time.Millisecond, 1001*time.Second), limit: LimitMaxClockError,
		},
		"error just under the bound mid-window": {status: goodSync(unsynced, 900*time.Millisecond, 1000*time.Second)},
		"large last offset refuses at once":     {status: goodSync(synced, 1500*time.Millisecond, 0), limit: LimitMaxClockError},
		"negative offset counts by magnitude":   {status: goodSync(synced, -1001*time.Millisecond, 0), limit: LimitMaxClockError},
		"offset exactly the bound":              {status: goodSync(synced, -time.Second, 0)},
		"tighter drift bound passes": {
			status: goodSync(unsynced, 641*time.Millisecond, time.Hour),
			limits: ClockLimits{MaxSyncAge: time.Hour, MaxDriftPPM: 50, MaxClockError: time.Second},
		},
		"never synced, pending": {
			status: &nodev1.TimeSyncStatus{State: nodev1.TimeSyncState_TIME_SYNC_STATE_PENDING}, limit: LimitNoGoodSync,
		},
		"never synced, every poll failed": {
			status: &nodev1.TimeSyncStatus{State: unsynced, LastError: "192.0.2.1: i/o timeout"}, limit: LimitNoGoodSync,
		},
		"no time source": {
			status: &nodev1.TimeSyncStatus{State: nodev1.TimeSyncState_TIME_SYNC_STATE_NOT_CONFIGURED}, limit: LimitNoGoodSync,
		},
		"synced without an offset": {
			status: &nodev1.TimeSyncStatus{State: synced, LastSync: timestamppb.New(gateNow)}, limit: LimitNoGoodSync,
		},
		"no status": {status: nil, limit: LimitNoGoodSync},
		"sources disagree inside the window": {status: func() *nodev1.TimeSyncStatus {
			st := goodSync(unsynced, 0, time.Minute)
			st.AdjustmentRefused = true
			st.LastError = "timesync: sources disagree"
			return st
		}(), limit: LimitAdjustmentRefused},
		"last sync after now counts as fresh": {status: goodSync(synced, 0, -time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			l := tc.limits
			if l == (ClockLimits{}) {
				l = limits
			}
			st := tc.status
			err := ClockGate(func() *nodev1.TimeSyncStatus { return st }, l, func() time.Time { return gateNow })()
			if tc.limit == "" {
				if err != nil {
					t.Fatalf("ClockGate = %v, want ok", err)
				}
				return
			}
			var refusal *ClockRefusal
			if !errors.As(err, &refusal) {
				t.Fatalf("ClockGate = %v, want a ClockRefusal naming %q", err, tc.limit)
			}
			if refusal.Limit != tc.limit {
				t.Fatalf("refused on %q (%v), want %q", refusal.Limit, err, tc.limit)
			}
			if err.Error() == "" {
				t.Fatal("the refusal has no reason")
			}
		})
	}
}

func TestEstimatedClockError(t *testing.T) {
	for _, tc := range []struct {
		offset, age time.Duration
		ppm         uint32
		want        time.Duration
	}{
		{0, time.Hour, 100, 360 * time.Millisecond},
		{-20 * time.Millisecond, 0, 100, 20 * time.Millisecond},
		{5 * time.Millisecond, 1000 * time.Second, 100, 105 * time.Millisecond},
		{0, 24 * time.Hour, 500, 43200 * time.Millisecond},
	} {
		if got := EstimatedClockError(tc.offset, tc.age, tc.ppm); got != tc.want {
			t.Errorf("EstimatedClockError(%v, %v, %d) = %v, want %v", tc.offset, tc.age, tc.ppm, got, tc.want)
		}
	}
}

func statusString(t *testing.T, resp []byte) string {
	t.Helper()
	var r respForTest
	if _, err := asn1.Unmarshal(resp, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Status.StatusString) == 0 {
		return ""
	}
	return r.Status.StatusString[0]
}
