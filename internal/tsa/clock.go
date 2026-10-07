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
	"fmt"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// The limits a ClockRefusal names. They match the pki.tsa config keys where
// there is one.
const (
	// LimitNoGoodSync: time sync has not had a good sync this boot.
	LimitNoGoodSync = "no_good_sync"
	// LimitAdjustmentRefused: the latest answered round was not applied.
	LimitAdjustmentRefused = "adjustment_refused"
	// LimitMaxSyncAge: the last good sync is older than MaxSyncAge.
	LimitMaxSyncAge = "max_sync_age"
	// LimitMaxClockError: the estimated clock error is above MaxClockError.
	LimitMaxClockError = "max_clock_error"
)

// ClockLimits bound how far the TSA trusts the clock between good syncs.
type ClockLimits struct {
	// MaxSyncAge is how long after the last good sync the TSA keeps
	// stamping while later polls fail.
	MaxSyncAge time.Duration
	// MaxDriftPPM is the drift rate assumed since the last good sync.
	MaxDriftPPM uint32
	// MaxClockError bounds the estimated clock error. It must not exceed the
	// accuracy tokens claim.
	MaxClockError time.Duration
}

// ClockRefusal is why ClockGate refused the clock. Limit is one of the
// Limit constants; Value is what was measured against it and Bound the
// limit's setting, both empty where they do not apply.
type ClockRefusal struct {
	Limit  string
	Value  string
	Bound  string
	Detail string
}

func (r *ClockRefusal) Error() string {
	switch r.Limit {
	case LimitNoGoodSync:
		if r.Detail != "" {
			return "no good time sync this boot: " + r.Detail
		}
		return "no good time sync this boot"
	case LimitAdjustmentRefused:
		return "the latest time sync round was refused: " + r.Detail
	case LimitMaxSyncAge:
		return fmt.Sprintf("the last good time sync was %s ago, more than %s=%s", r.Value, LimitMaxSyncAge, r.Bound)
	default:
		return fmt.Sprintf("the estimated clock error is %s, more than %s=%s", r.Value, LimitMaxClockError, r.Bound)
	}
}

// Public is the refusal as the client may see it: the limit and its value,
// without server names or other internal detail.
func (r *ClockRefusal) Public() string {
	if r.Bound == "" {
		return r.Limit
	}
	return fmt.Sprintf("%s=%s exceeded (%s)", r.Limit, r.Bound, r.Value)
}

// EstimatedClockError is how far the clock may be off: the magnitude of the
// offset measured at the last good sync plus ppm parts per million of the
// time since it.
func EstimatedClockError(offset, age time.Duration, ppm uint32) time.Duration {
	return offset.Abs() + age/1_000_000*time.Duration(ppm) + age%1_000_000*time.Duration(ppm)/1_000_000
}

// ClockGate returns the TSA's clock check over the node's time-sync status.
// The clock may be stamped while the last good sync of this boot is no
// older than MaxSyncAge and the estimated clock error (EstimatedClockError
// over the offset it measured and the time since) is no larger than
// MaxClockError. A poll that no server answered does not refuse on its own,
// so one lost packet does not stop the TSA; a round that was answered but
// not applied (adjustment_refused: the sources disagree, or a step was
// refused) does, until the next good sync. A node with no time source never
// syncs and is always refused. Unlike certificate signing there is no
// override: a timestamp is nothing but a claim about the time.
func ClockGate(status func() *nodev1.TimeSyncStatus, limits ClockLimits, now func() time.Time) func() error {
	return func() error {
		st := status()
		if st == nil {
			return &ClockRefusal{Limit: LimitNoGoodSync, Detail: "the time sync status is unavailable"}
		}
		if st.GetLastSync() == nil || st.GetLastOffset() == nil {
			return &ClockRefusal{Limit: LimitNoGoodSync, Detail: st.GetLastError()}
		}
		if st.GetAdjustmentRefused() {
			return &ClockRefusal{Limit: LimitAdjustmentRefused, Detail: st.GetLastError()}
		}
		age := max(now().Sub(st.GetLastSync().AsTime()), 0)
		if age > limits.MaxSyncAge {
			return &ClockRefusal{Limit: LimitMaxSyncAge, Value: age.Round(time.Millisecond).String(), Bound: limits.MaxSyncAge.String()}
		}
		if est := EstimatedClockError(st.GetLastOffset().AsDuration(), age, limits.MaxDriftPPM); est > limits.MaxClockError {
			return &ClockRefusal{Limit: LimitMaxClockError, Value: est.String(), Bound: limits.MaxClockError.String()}
		}
		return nil
	}
}
