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
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

// Media types (RFC 3161 section 3.4).
const (
	ContentTypeQuery = "application/timestamp-query"
	ContentTypeReply = "application/timestamp-reply"
)

// maxRequestBytes caps a TimeStampReq. A real one is about a hundred bytes;
// the cap leaves room for a SHA-512 imprint, a policy, a long nonce and
// extensions (which are refused, but must be read to be refused).
const maxRequestBytes = 16 << 10

// HandlerOptions configures the TSA's HTTP handler.
type HandlerOptions struct {
	// AllowedNetworks, when non-empty, are the only client networks
	// answered. Anyone else gets 403 before the request is read.
	AllowedNetworks []netip.Prefix
	// RequestsPerMinute and Burst size each client's token bucket. Both
	// are required: the limit cannot be switched off.
	RequestsPerMinute int
	Burst             int
	// Now and Logf default to time.Now and discarding.
	Now  func() time.Time
	Logf func(string, ...any)
}

type handler struct {
	r       *Responder
	allowed []netip.Prefix
	limit   *limiter
	logf    func(string, ...any)
}

// NewHandler returns the TSA's HTTP handler: POST of an
// application/timestamp-query to the root path, answered with an
// application/timestamp-reply. The client's network is checked first, then
// its rate limit, and only then is the request read.
func NewHandler(r *Responder, opts HandlerOptions) (http.Handler, error) {
	if r == nil {
		return nil, errors.New("tsa: NewHandler: a responder is required")
	}
	if opts.RequestsPerMinute <= 0 || opts.Burst <= 0 {
		return nil, fmt.Errorf("tsa: NewHandler: the rate limit needs a positive rate and burst, got %d a minute and %d", opts.RequestsPerMinute, opts.Burst)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	return &handler{
		r: r, allowed: opts.AllowedNetworks, logf: opts.Logf,
		limit: newLimiter(opts.RequestsPerMinute, opts.Burst, opts.Now),
	}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ap, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		h.logf("tsa: refused a client with an unreadable address %q", req.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	client := ap.Addr().Unmap()
	if !h.permitted(client) {
		h.logf("tsa: refused %s: outside the allowed networks", client)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if ok, wait := h.limit.allow(client); !ok {
		secs := int(math.Ceil(wait.Seconds()))
		if secs < 1 {
			secs = 1
		}
		h.logf("tsa: refused %s: over its rate limit (retry in %ds)", client, secs)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the time-stamp authority takes POST", http.StatusMethodNotAllowed)
		return
	}
	if mt, _, err := mime.ParseMediaType(req.Header.Get("Content-Type")); err != nil || mt != ContentTypeQuery {
		http.Error(w, "the request must be "+ContentTypeQuery, http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, maxRequestBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "the request is too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.logf("tsa: reading the request from %s failed: %v", client, err)
		http.Error(w, "the request could not be read", http.StatusBadRequest)
		return
	}
	resp, out, err := h.r.Respond(req.Context(), body)
	if err != nil {
		h.logf("tsa: answering %s failed: %v", client, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if out.Granted {
		h.logf("tsa: %s: granted token %s", client, out.Serial.Text(16))
	} else {
		h.logf("tsa: %s: rejected with %s", client, out.Fail)
	}
	w.Header().Set("Content-Type", ContentTypeReply)
	_, _ = w.Write(resp)
}

func (h *handler) permitted(a netip.Addr) bool {
	if len(h.allowed) == 0 {
		return true
	}
	for _, p := range h.allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Serve starts a plain-HTTP server for h on addr and returns a stop closure.
// The listen is synchronous, so a bind failure reaches the caller. Plain HTTP
// is what RFC 3161 section 3.4 describes: the token carries its own integrity
// and nothing in it is confidential.
func Serve(_ context.Context, addr string, h http.Handler) (func(context.Context) error, error) {
	stop, _, err := serveOn(addr, h)
	return stop, err
}

func serveOn(addr string, h http.Handler) (func(context.Context) error, string, error) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("tsa: listen %s: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	go func() { _ = srv.Serve(lis) }()
	return srv.Shutdown, lis.Addr().String(), nil
}
