package qga

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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeHost struct {
	version    string
	hostname   string
	hostErr    error
	uname      Uname
	now        time.Time
	ifaces     []Interface
	ifaceErr   error
	shutdowns  []string
	shutdownFn func(string) error
}

func (h *fakeHost) Version() string                  { return h.version }
func (h *fakeHost) HostName() (string, error)        { return h.hostname, h.hostErr }
func (h *fakeHost) Uname() (Uname, error)            { return h.uname, nil }
func (h *fakeHost) Now() time.Time                   { return h.now }
func (h *fakeHost) Interfaces() ([]Interface, error) { return h.ifaces, h.ifaceErr }
func (h *fakeHost) Shutdown(mode string) error {
	h.shutdowns = append(h.shutdowns, mode)
	if h.shutdownFn != nil {
		return h.shutdownFn(mode)
	}

	return nil
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		version:  "v0.1.0-rc.2",
		hostname: "ca-root-1",
		uname:    Uname{Release: "6.12.8-cryptos", Version: "#1 SMP PREEMPT_DYNAMIC", Machine: "x86_64"},
		now:      time.Unix(1_800_000_000, 123),
		ifaces: []Interface{
			{Name: "lo", IPAddresses: []IPAddress{{Type: "ipv4", Address: "127.0.0.1", Prefix: 8}}},
			{Name: "eth0", HardwareAddress: "52:54:00:12:34:56", IPAddresses: []IPAddress{
				{Type: "ipv4", Address: "192.0.2.10", Prefix: 24},
				{Type: "ipv6", Address: "2001:db8::10", Prefix: 64},
			}},
		},
	}
}

// feed runs input through a fresh session in one write and returns the output.
func feed(t *testing.T, h Host, input string) string {
	t.Helper()
	var out bytes.Buffer
	s := newSession(h, &out, t.Logf)
	s.feed([]byte(input))

	return out.String()
}

// lines splits newline-terminated responses, failing on a missing final newline.
func lines(t *testing.T, out string) []string {
	t.Helper()
	if out == "" {
		return nil
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output %q does not end in a newline", out)
	}

	return strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

func decode(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("response %q is not JSON: %v", line, err)
	}

	return m
}

func one(t *testing.T, h Host, input string) map[string]any {
	t.Helper()
	ls := lines(t, feed(t, h, input))
	if len(ls) != 1 {
		t.Fatalf("got %d responses %q, want 1", len(ls), ls)
	}

	return decode(t, ls[0])
}

func wantError(t *testing.T, resp map[string]any, class, descPrefix string) {
	t.Helper()
	e, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("response %v is not an error", resp)
	}
	if e["class"] != class {
		t.Errorf("error class = %v, want %s", e["class"], class)
	}
	if d, _ := e["desc"].(string); !strings.HasPrefix(d, descPrefix) {
		t.Errorf("error desc = %q, want prefix %q", d, descPrefix)
	}
}

func TestGuestSyncReturnsID(t *testing.T) {
	resp := one(t, newFakeHost(), `{"execute":"guest-sync","arguments":{"id":1234567}}`)
	if resp["return"] != float64(1234567) {
		t.Fatalf("return = %v, want 1234567", resp["return"])
	}
}

func TestGuestSyncLargeIDIsExact(t *testing.T) {
	out := feed(t, newFakeHost(), `{"execute":"guest-sync","arguments":{"id":9007199254740993}}`)
	if out != `{"return":9007199254740993}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestGuestSyncNeedsIntegerID(t *testing.T) {
	wantError(t, one(t, newFakeHost(), `{"execute":"guest-sync"}`), "GenericError", "Parameter 'id' is missing")
	wantError(t, one(t, newFakeHost(), `{"execute":"guest-sync","arguments":{"id":"x"}}`), "GenericError", "Invalid parameter type for 'id'")
}

func TestGuestSyncDelimitedWritesFFFirst(t *testing.T) {
	out := feed(t, newFakeHost(), `{"execute":"guest-sync-delimited","arguments":{"id":42}}`)
	if out != "\xff"+`{"return":42}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

// TestProxmoxExchange is the exact pair Proxmox's QMPClient writes in one go,
// and the regex it reads the reply with.
func TestProxmoxExchange(t *testing.T) {
	in := `{"arguments":{"id":4242011},"execute":"guest-sync-delimited"}` + "\n" + `{"execute":"guest-ping","arguments":null}` + "\n"
	out := feed(t, newFakeHost(), in)
	if out != "\xff"+`{"return":4242011}`+"\n"+`{"return":{}}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestPingAndIDEcho(t *testing.T) {
	out := feed(t, newFakeHost(), `{"execute":"guest-ping","id":"abc"}{"execute":"guest-ping","id":7}`)
	ls := lines(t, out)
	if len(ls) != 2 {
		t.Fatalf("responses = %q", ls)
	}
	if ls[0] != `{"return":{},"id":"abc"}` || ls[1] != `{"return":{},"id":7}` {
		t.Fatalf("responses = %q", ls)
	}
}

func TestGuestInfoListsOnlyTheAllowList(t *testing.T) {
	resp := one(t, newFakeHost(), `{"execute":"guest-info"}`)
	ret := resp["return"].(map[string]any)
	if ret["version"] != "v0.1.0-rc.2" {
		t.Errorf("version = %v", ret["version"])
	}
	var names []string
	for _, c := range ret["supported_commands"].([]any) {
		m := c.(map[string]any)
		names = append(names, m["name"].(string))
		if m["enabled"] != true {
			t.Errorf("%v not enabled", m["name"])
		}
		wantSR := m["name"] != "guest-shutdown"
		if m["success-response"] != wantSR {
			t.Errorf("%v success-response = %v, want %v", m["name"], m["success-response"], wantSR)
		}
	}
	want := []string{
		"guest-sync", "guest-sync-delimited", "guest-ping", "guest-info", "guest-get-osinfo",
		"guest-get-host-name", "guest-get-time", "guest-get-timezone", "guest-network-get-interfaces",
		"guest-shutdown", "guest-fsfreeze-status",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("supported_commands = %v, want %v", names, want)
	}
}

func TestGetOSInfo(t *testing.T) {
	ret := one(t, newFakeHost(), `{"execute":"guest-get-osinfo"}`)["return"].(map[string]any)
	want := map[string]any{
		"id": "cryptos", "name": "CryptOS", "pretty-name": "CryptOS v0.1.0-rc.2",
		"version": "v0.1.0-rc.2", "version-id": "v0.1.0-rc.2",
		"kernel-release": "6.12.8-cryptos", "kernel-version": "#1 SMP PREEMPT_DYNAMIC", "machine": "x86_64",
	}
	if !reflect.DeepEqual(ret, want) {
		t.Fatalf("osinfo = %v, want %v", ret, want)
	}
}

func TestGetHostName(t *testing.T) {
	ret := one(t, newFakeHost(), `{"execute":"guest-get-host-name"}`)["return"].(map[string]any)
	if ret["host-name"] != "ca-root-1" {
		t.Fatalf("host-name = %v", ret["host-name"])
	}
	h := newFakeHost()
	h.hostErr = errors.New("boom")
	wantError(t, one(t, h, `{"execute":"guest-get-host-name"}`), "GenericError", "")
}

func TestGetTime(t *testing.T) {
	out := feed(t, newFakeHost(), `{"execute":"guest-get-time"}`)
	if out != `{"return":1800000000000000123}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestGetTimezone(t *testing.T) {
	h := newFakeHost()
	h.now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.FixedZone("EST", -5*3600))
	ret := one(t, h, `{"execute":"guest-get-timezone"}`)["return"].(map[string]any)
	if ret["zone"] != "EST" || ret["offset"] != float64(-18000) {
		t.Fatalf("timezone = %v", ret)
	}
	h.now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ret = one(t, h, `{"execute":"guest-get-timezone"}`)["return"].(map[string]any)
	if ret["zone"] != "UTC" || ret["offset"] != float64(0) {
		t.Fatalf("timezone = %v", ret)
	}
}

func TestNetworkGetInterfaces(t *testing.T) {
	out := feed(t, newFakeHost(), `{"execute":"guest-network-get-interfaces"}`)
	want := `{"return":[{"name":"lo","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"127.0.0.1","prefix":8}]},` +
		`{"name":"eth0","hardware-address":"52:54:00:12:34:56","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"192.0.2.10","prefix":24},` +
		`{"ip-address-type":"ipv6","ip-address":"2001:db8::10","prefix":64}]}]}` + "\n"
	if out != want {
		t.Fatalf("output =\n%s\nwant\n%s", out, want)
	}
	h := newFakeHost()
	h.ifaces = nil
	if out := feed(t, h, `{"execute":"guest-network-get-interfaces"}`); out != `{"return":[]}`+"\n" {
		t.Fatalf("empty output = %q", out)
	}
}

func TestFsfreezeStatusIsThawed(t *testing.T) {
	if out := feed(t, newFakeHost(), `{"execute":"guest-fsfreeze-status"}`); out != `{"return":"thawed"}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestShutdownModes(t *testing.T) {
	for _, tc := range []struct{ in, mode string }{
		{`{"execute":"guest-shutdown"}`, "powerdown"},
		{`{"execute":"guest-shutdown","arguments":null}`, "powerdown"},
		{`{"execute":"guest-shutdown","arguments":{"mode":"powerdown"}}`, "powerdown"},
		{`{"execute":"guest-shutdown","arguments":{"mode":"halt"}}`, "halt"},
		{`{"execute":"guest-shutdown","arguments":{"mode":"reboot"}}`, "reboot"},
	} {
		h := newFakeHost()
		if out := feed(t, h, tc.in); out != "" {
			t.Errorf("%s: output %q, want none (success-response false)", tc.in, out)
		}
		if !reflect.DeepEqual(h.shutdowns, []string{tc.mode}) {
			t.Errorf("%s: shutdowns = %v, want [%s]", tc.in, h.shutdowns, tc.mode)
		}
	}
}

func TestShutdownBadModeAndFailure(t *testing.T) {
	h := newFakeHost()
	wantError(t, one(t, h, `{"execute":"guest-shutdown","arguments":{"mode":"suspend"}}`), "GenericError", "Parameter 'mode'")
	if len(h.shutdowns) != 0 {
		t.Fatalf("shutdown called for a bad mode: %v", h.shutdowns)
	}
	h.shutdownFn = func(string) error { return errors.New("no") }
	wantError(t, one(t, h, `{"execute":"guest-shutdown"}`), "GenericError", "")
}

func TestRefusedCommandsGetDisabledShape(t *testing.T) {
	for _, name := range []string{
		"guest-exec", "guest-exec-status", "guest-file-open", "guest-file-read", "guest-file-write",
		"guest-file-close", "guest-file-seek", "guest-file-flush", "guest-set-user-password",
		"guest-ssh-get-authorized-keys", "guest-ssh-add-authorized-keys", "guest-ssh-remove-authorized-keys",
		"guest-fsfreeze-freeze", "guest-fsfreeze-freeze-list", "guest-fsfreeze-thaw",
		"guest-set-time", "guest-suspend-disk", "guest-set-vcpus", "guest-get-fsinfo", "guest-fstrim",
	} {
		h := newFakeHost()
		in := fmt.Sprintf(`{"execute":%q,"arguments":{"path":"/etc/shadow","username":"root","password":"c2VjcmV0"},"id":1}`, name)
		resp := one(t, h, in)
		wantError(t, resp, "CommandNotFound", "Command "+name+" has been disabled")
		if resp["id"] != float64(1) {
			t.Errorf("%s: id not echoed: %v", name, resp)
		}
		if len(h.shutdowns) != 0 {
			t.Errorf("%s: triggered a shutdown", name)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	wantError(t, one(t, newFakeHost(), `{"execute":"guest-frobnicate"}`), "CommandNotFound", "The command guest-frobnicate has not been found")
}

func TestRefusedArgumentsAreNeverLogged(t *testing.T) {
	var logged strings.Builder
	var out bytes.Buffer
	s := newSession(newFakeHost(), &out, func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) })
	s.feed([]byte(`{"execute":"guest-set-user-password","arguments":{"username":"root","password":"c2VjcmV0"}}`))
	if strings.Contains(logged.String(), "c2VjcmV0") || strings.Contains(logged.String(), "root") {
		t.Fatalf("log carries the arguments: %s", logged.String())
	}
	if !strings.Contains(logged.String(), "guest-set-user-password") {
		t.Fatalf("log does not name the refused command: %s", logged.String())
	}
}

func TestMalformedInput(t *testing.T) {
	for _, tc := range []struct{ in, class, desc string }{
		{`{"execute":"guest-ping",}`, "GenericError", "JSON parse error"},
		{`{"execute":"guest-ping"]`, "GenericError", "JSON parse error"},
		{`[1,2,3]`, "GenericError", "QMP input must be a JSON object"},
		{`"guest-ping" `, "GenericError", "QMP input must be a JSON object"},
		{`nonsense `, "GenericError", "JSON parse error"},
		{`{"arguments":{}}`, "GenericError", "QMP input lacks member 'execute'"},
		{`{"execute":42}`, "GenericError", "QMP input member 'execute' must be a string"},
		{`{"execute":"guest-ping","bogus":1}`, "GenericError", "QMP input member 'bogus' is unexpected"},
		{`{"execute":"guest-ping","arguments":[1]}`, "GenericError", "QMP input member 'arguments' must be an object"},
		{`{"execute":"guest-ping","arguments":{"x":1}}`, "GenericError", "Parameter 'x' is unexpected"},
		{`{"execute":"guest-shutdown","arguments":{"mode":"halt","force":true}}`, "GenericError", "Parameter 'force' is unexpected"},
	} {
		wantError(t, one(t, newFakeHost(), tc.in), tc.class, tc.desc)
	}
}

func TestMalformedInputDoesNotStopTheAgent(t *testing.T) {
	ls := lines(t, feed(t, newFakeHost(), `{"execute":}{"execute":"guest-ping"}`))
	if len(ls) != 2 || ls[1] != `{"return":{}}` {
		t.Fatalf("responses = %q", ls)
	}
}

func TestStringsWithBracesAndEscapes(t *testing.T) {
	in := `{"execute":"guest-ping","id":"a}\"{[b"}`
	if out := feed(t, newFakeHost(), in); out != `{"return":{},"id":"a}\"{[b"}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestSplitAcrossReads(t *testing.T) {
	var out bytes.Buffer
	s := newSession(newFakeHost(), &out, t.Logf)
	msg := `  {"execute":"guest-ping","id":"x"}` + "\r\n"
	for i := range len(msg) {
		s.feed([]byte{msg[i]})
	}
	if out.String() != `{"return":{},"id":"x"}`+"\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestFFResyncDropsPartialRequest(t *testing.T) {
	out := feed(t, newFakeHost(), `{"execute":"guest-shutdown","argu`+"\xff"+`{"execute":"guest-ping"}`)
	if out != `{"return":{}}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestOversizedRequestIsRefusedAndSkipped(t *testing.T) {
	big := `{"execute":"guest-ping","id":"` + strings.Repeat("A", maxRequestBytes) + `"}`
	h := newFakeHost()
	ls := lines(t, feed(t, h, big+`{"execute":"guest-ping","id":2}`))
	if len(ls) != 2 {
		t.Fatalf("responses = %q", ls)
	}
	wantError(t, decode(t, ls[0]), "GenericError", "JSON request too large")
	if ls[1] != `{"return":{},"id":2}` {
		t.Fatalf("second response = %q", ls[1])
	}
}

func TestOversizedThenResync(t *testing.T) {
	big := `{"execute":"guest-ping","id":"` + strings.Repeat("A", maxRequestBytes+10)
	out := feed(t, newFakeHost(), big+"\xff"+`{"execute":"guest-ping"}`)
	if out != `{"return":{}}`+"\n" {
		t.Fatalf("output = %q", out)
	}
}

func TestDeepNestingIsRefused(t *testing.T) {
	deep := `{"execute":"guest-ping","id":` + strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1) + `}`
	ls := lines(t, feed(t, newFakeHost(), deep+`{"execute":"guest-ping"}`))
	if len(ls) != 2 {
		t.Fatalf("responses = %q", ls)
	}
	wantError(t, decode(t, ls[0]), "GenericError", "JSON request nested too deeply")
	if ls[1] != `{"return":{}}` {
		t.Fatalf("second response = %q", ls[1])
	}
}

func TestOversizedScalarIsRefused(t *testing.T) {
	ls := lines(t, feed(t, newFakeHost(), strings.Repeat("x", maxRequestBytes+5)+` {"execute":"guest-ping"}`))
	if len(ls) != 2 {
		t.Fatalf("responses = %q", ls)
	}
	wantError(t, decode(t, ls[0]), "GenericError", "JSON request too large")
}

func TestResetDropsPartialInput(t *testing.T) {
	var out bytes.Buffer
	s := newSession(newFakeHost(), &out, t.Logf)
	s.feed([]byte(`{"execute":"guest-shutdown"`))
	s.reset()
	s.feed([]byte(`{"execute":"guest-ping"}`))
	if out.String() != `{"return":{}}`+"\n" {
		t.Fatalf("output = %q", out.String())
	}
}
