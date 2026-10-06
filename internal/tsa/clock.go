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
	"errors"
	"fmt"
	"strings"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// ClockGate returns the TSA's clock check over the node's time-sync status.
// The clock may be stamped only while the latest time sync succeeded
// (SYNCED) and the offset it measured is no larger than the accuracy every
// token claims. That refuses a node that has not synced this boot, one whose
// sources disagree or whose latest step was refused (both leave the state
// UNSYNCED), and one with no time source at all, which never syncs. Unlike
// certificate signing there is no override: a timestamp is nothing but a
// claim about the time.
func ClockGate(status func() *nodev1.TimeSyncStatus, accuracy time.Duration) func() error {
	return func() error {
		st := status()
		if st == nil {
			return errors.New("the time sync status is unavailable")
		}
		if st.GetState() != nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED {
			reason := fmt.Sprintf("time sync is %s, not SYNCED", strings.TrimPrefix(st.GetState().String(), "TIME_SYNC_STATE_"))
			if e := st.GetLastError(); e != "" {
				reason += ": " + e
			}
			return errors.New(reason)
		}
		if st.GetLastOffset() == nil {
			return errors.New("time sync reports no measured offset")
		}
		if off := st.GetLastOffset().AsDuration().Abs(); off > accuracy {
			return fmt.Errorf("the latest time sync measured an offset of %s, more than the %s accuracy tokens claim", off, accuracy)
		}
		return nil
	}
}
