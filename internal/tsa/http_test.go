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
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

type httpFixture struct {
	t     *testing.T
	s     *staticSigner
	clock *testClock
	h     http.Handler
}

func newHTTPFixture(t *testing.T, opts HandlerOptions) *httpFixture {
	t.Helper()
	_, s := newTSA(t)
	f := &httpFixture{t: t, s: s, clock: &testClock{now: time.Now().UTC()}}
	r := newTestResponder(t, s, nil)
	if opts.RequestsPerMinute == 0 {
		opts.RequestsPerMinute = 600
	}
	if opts.Burst == 0 {
		opts.Burst = 100
	}
	opts.Now = f.clock.Now
	h, err := NewHandler(r, opts)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	f.h = h
	return f
}

func (f *httpFixture) do(method, path, remote, contentType string, body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = remote
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *httpFixture) query(remote string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(http.MethodPost, "/", remote, ContentTypeQuery, encodeRequest(f.t, sha256Request(nil, true)))
}

func TestHandlerAnswersAQueryWithAReply(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{})
	rec := f.query("192.0.2.10:40000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentTypeReply {
		t.Errorf("Content-Type = %q, want %q", ct, ContentTypeReply)
	}
	verifiedToken(t, rec.Body.Bytes(), f.s.cert)
}

func TestHandlerAcceptsAContentTypeWithParameters(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{})
	rec := f.do(http.MethodPost, "/", "192.0.2.10:1", "Application/Timestamp-Query; charset=binary", encodeRequest(t, sha256Request(nil, false)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestHandlerAnswersAMalformedQueryWithARejection(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{})
	rec := f.do(http.MethodPost, "/", "192.0.2.10:1", ContentTypeQuery, []byte("junk"))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ContentTypeReply {
		t.Fatalf("status = %d, Content-Type %q; a bad query still gets a TimeStampResp", rec.Code, rec.Header().Get("Content-Type"))
	}
	r := parseResponse(t, rec.Body.Bytes())
	if r.Status.Status != 2 || r.Status.FailInfo.At(int(FailBadDataFormat)) != 1 {
		t.Fatalf("status %d failInfo %v, want badDataFormat", r.Status.Status, r.Status.FailInfo)
	}
}

func TestHandlerRefusesWhatIsNotAQuery(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{})
	q := encodeRequest(t, sha256Request(nil, false))
	big := make([]byte, maxRequestBytes+1)
	for name, tc := range map[string]struct {
		method, path, ct string
		body             []byte
		want             int
	}{
		"GET":               {http.MethodGet, "/", "", nil, http.StatusMethodNotAllowed},
		"another path":      {http.MethodPost, "/tsa", ContentTypeQuery, q, http.StatusNotFound},
		"no content type":   {http.MethodPost, "/", "", q, http.StatusUnsupportedMediaType},
		"wrong media type":  {http.MethodPost, "/", "application/octet-stream", q, http.StatusUnsupportedMediaType},
		"oversized request": {http.MethodPost, "/", ContentTypeQuery, big, http.StatusRequestEntityTooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(tc.method, tc.path, "192.0.2.10:1", tc.ct, tc.body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
				t.Errorf("Allow = %q, want POST", rec.Header().Get("Allow"))
			}
		})
	}
}

func TestHandlerAnswersOnlyTheAllowedNetworks(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{AllowedNetworks: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8:1::/48"),
		netip.MustParsePrefix("198.51.100.7/32"),
	}})
	for remote, want := range map[string]int{
		"192.0.2.44:5000":               http.StatusOK,
		"[2001:db8:1:2::9]:5000":        http.StatusOK,
		"198.51.100.7:5000":             http.StatusOK,
		"[::ffff:192.0.2.45]:5000":      http.StatusOK,
		"198.51.100.8:5000":             http.StatusForbidden,
		"203.0.113.1:5000":              http.StatusForbidden,
		"[2001:db8:2::1]:5000":          http.StatusForbidden,
		"not an address":                http.StatusForbidden,
		"[::ffff:203.0.113.9]:5000":     http.StatusForbidden,
		"[fe80::1%eth0]:5000":           http.StatusForbidden,
		"[2001:db8:1:ffff::ffff]:65535": http.StatusOK,
	} {
		if rec := f.query(remote); rec.Code != want {
			t.Errorf("client %s: status = %d, want %d", remote, rec.Code, want)
		}
	}
}

func TestHandlerRefusesAForbiddenClientBeforeReadingIt(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{AllowedNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	body := &countingReader{r: bytes.NewReader(encodeRequest(t, sha256Request(nil, false)))}
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.RemoteAddr = "203.0.113.1:1"
	req.Header.Set("Content-Type", ContentTypeQuery)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || body.n != 0 {
		t.Fatalf("status = %d, %d body bytes read; want 403 with nothing read", rec.Code, body.n)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestHandlerRateLimitsEachClient(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{RequestsPerMinute: 60, Burst: 2})
	for i := range 2 {
		if rec := f.query("192.0.2.10:1"); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the burst: status %d", i, rec.Code)
		}
	}
	rec := f.query("192.0.2.10:2")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request over the burst: status %d, want 429", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After = %q, want 1", ra)
	}
	if rec := f.query("192.0.2.11:1"); rec.Code != http.StatusOK {
		t.Fatalf("another client was limited too: status %d", rec.Code)
	}
	f.clock.advance(time.Second)
	if rec := f.query("192.0.2.10:3"); rec.Code != http.StatusOK {
		t.Fatalf("after a second at 60 a minute: status %d", rec.Code)
	}
	if rec := f.query("192.0.2.10:3"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("one second refills one request only: status %d", rec.Code)
	}
}

func TestHandlerRateLimitsAnIPv6ClientByItsSlash64(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{RequestsPerMinute: 60, Burst: 1})
	if rec := f.query("[2001:db8:5:6::1]:1"); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := f.query("[2001:db8:5:6:ffff::2]:1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("another address in the same /64: status %d, want 429", rec.Code)
	}
	if rec := f.query("[2001:db8:5:7::1]:1"); rec.Code != http.StatusOK {
		t.Fatalf("a different /64: status %d", rec.Code)
	}
}

func TestHandlerRateLimitsAnIPv4MappedClientAsIPv4(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{RequestsPerMinute: 60, Burst: 1})
	if rec := f.query("192.0.2.20:1"); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := f.query("[::ffff:192.0.2.20]:1"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the mapped form of the same client: status %d, want 429", rec.Code)
	}
	if rec := f.query("[::ffff:192.0.2.21]:1"); rec.Code != http.StatusOK {
		t.Fatalf("a different IPv4 client in mapped form: status %d", rec.Code)
	}
}

func TestLimiterForgetsIdleClients(t *testing.T) {
	clock := &testClock{now: time.Now()}
	l := newLimiter(60, 1, clock.Now)
	for i := range 10 {
		l.allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	clock.advance(2 * time.Minute)
	l.allow(netip.MustParseAddr("198.51.100.1"))
	if n := l.size(); n != 1 {
		t.Fatalf("%d buckets after the idle clients refilled, want 1", n)
	}
}

func TestLimiterRefusesNewClientsWhenFull(t *testing.T) {
	clock := &testClock{now: time.Now()}
	l := newLimiter(60, 1, clock.Now)
	l.max = 4
	for i := range 4 {
		if ok, _ := l.allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})); !ok {
			t.Fatalf("client %d refused", i)
		}
	}
	if ok, _ := l.allow(netip.MustParseAddr("198.51.100.1")); ok {
		t.Fatal("a new client was let in past the bucket cap while every bucket was busy")
	}
	clock.advance(2 * time.Minute)
	if ok, _ := l.allow(netip.MustParseAddr("198.51.100.1")); !ok {
		t.Fatal("a new client was refused after the busy buckets went idle")
	}
}

func TestNewHandlerRequiresARateLimit(t *testing.T) {
	_, s := newTSA(t)
	r := newTestResponder(t, s, nil)
	if _, err := NewHandler(r, HandlerOptions{Burst: 1}); err == nil {
		t.Error("NewHandler accepted no rate")
	}
	if _, err := NewHandler(r, HandlerOptions{RequestsPerMinute: 1}); err == nil {
		t.Error("NewHandler accepted no burst")
	}
}

func syncStatus(state nodev1.TimeSyncState, offset time.Duration) func() *nodev1.TimeSyncStatus {
	return func() *nodev1.TimeSyncStatus {
		st := &nodev1.TimeSyncStatus{State: state}
		if state == nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED {
			st.LastOffset = durationpb.New(offset)
		}
		return st
	}
}

func TestClockGate(t *testing.T) {
	const acc = time.Second
	for name, tc := range map[string]struct {
		status func() *nodev1.TimeSyncStatus
		ok     bool
	}{
		"synced, small offset":         {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED, 20*time.Millisecond), true},
		"synced, offset at accuracy":   {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED, -acc), true},
		"synced, offset over":          {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED, acc+time.Millisecond), false},
		"synced, negative offset over": {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED, -acc-time.Millisecond), false},
		"never synced":                 {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_PENDING, 0), false},
		"latest sync failed":           {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED, 0), false},
		"no time source":               {syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_NOT_CONFIGURED, 0), false},
		"synced without an offset": {func() *nodev1.TimeSyncStatus {
			return &nodev1.TimeSyncStatus{State: nodev1.TimeSyncState_TIME_SYNC_STATE_SYNCED}
		}, false},
		"no status": {func() *nodev1.TimeSyncStatus { return nil }, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := ClockGate(tc.status, acc)()
			if (err == nil) != tc.ok {
				t.Fatalf("ClockGate = %v, want ok=%t", err, tc.ok)
			}
		})
	}
}

func TestRespondRefusesWithTimeNotAvailableWhileTheClockIsGated(t *testing.T) {
	_, s := newTSA(t)
	var logs strings.Builder
	r, err := NewResponder(s, ResponderOptions{
		Policy:        testPolicy,
		Accuracy:      time.Second,
		TimeAvailable: ClockGate(syncStatus(nodev1.TimeSyncState_TIME_SYNC_STATE_UNSYNCED, 0), time.Second),
		Logf:          func(format string, args ...any) { logs.WriteString(format) },
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, out, err := r.Respond(context.Background(), encodeRequest(t, sha256Request(nil, false)))
	if err != nil {
		t.Fatal(err)
	}
	assertRejected(t, resp, out, FailTimeNotAvailable)
	if !strings.Contains(out.Reason, "UNSYNCED") {
		t.Errorf("reason %q does not say why", out.Reason)
	}
	if !strings.Contains(logs.String(), "rejected") {
		t.Error("the refusal is not logged")
	}
}

func TestServeAnswersOverTheNetwork(t *testing.T) {
	f := newHTTPFixture(t, HandlerOptions{})
	stop, addr, err := serveOn("127.0.0.1:0", f.h)
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer func() { _ = stop(context.Background()) }()
	resp, err := http.Post("http://"+addr+"/", ContentTypeQuery, bytes.NewReader(encodeRequest(t, sha256Request(nil, true))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	verifiedToken(t, body, f.s.cert)
}
