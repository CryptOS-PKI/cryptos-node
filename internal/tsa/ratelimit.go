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
	"math"
	"net/netip"
	"sync"
	"time"
)

// maxBuckets bounds the limiter's memory. A client that would need a new
// bucket while every bucket is in use is refused until some go idle, so a
// flood from many addresses fails closed instead of growing without limit.
const maxBuckets = 1 << 16

// sweepInterval is how often idle buckets are dropped.
const sweepInterval = time.Minute

// limiter is a per-client token bucket.
type limiter struct {
	rate  float64 // tokens per second
	burst float64
	now   func() time.Time
	max   int

	mu        sync.Mutex
	buckets   map[netip.Addr]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst int, now func() time.Time) *limiter {
	return &limiter{
		rate: float64(perMinute) / 60, burst: float64(burst), now: now, max: maxBuckets,
		buckets: map[netip.Addr]*bucket{}, lastSweep: now(),
	}
}

// clientKey is the bucket a client draws from: its IPv4 address, or its IPv6
// /64, so hopping addresses inside one allocation does not reset it.
func clientKey(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a
	}
	p, _ := a.Prefix(64)
	return p.Addr()
}

// allow takes a token for the client at a, or reports how long until one is
// available.
func (l *limiter) allow(a netip.Addr) (bool, time.Duration) {
	key := clientKey(a)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= sweepInterval {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.max {
			l.sweep(now)
			if len(l.buckets) >= l.max {
				return false, sweepInterval
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// sweep drops the buckets that have refilled: forgetting them changes
// nothing, since a new bucket starts full.
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
	l.lastSweep = now
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
