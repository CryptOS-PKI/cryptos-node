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
	"fmt"
	"io"
	"sort"
	"time"
)

// Error classes, as qemu-ga sends them.
const (
	classGeneric         = "GenericError"
	classCommandNotFound = "CommandNotFound"
)

type qerror struct {
	Class string `json:"class"`
	Desc  string `json:"desc"`
}

func (e *qerror) Error() string { return e.Class + ": " + e.Desc }

func generic(format string, args ...any) *qerror {
	return &qerror{Class: classGeneric, Desc: fmt.Sprintf(format, args...)}
}

type response struct {
	Return any             `json:"return,omitempty"`
	Error  *qerror         `json:"error,omitempty"`
	ID     json.RawMessage `json:"id,omitempty"`
}

// result is what a command handler returns: a value, an error, or (for
// guest-shutdown) nothing at all.
type result struct {
	value      any
	err        *qerror
	noResponse bool
	delimited  bool
}

type handler func(s *session, args map[string]json.RawMessage) result

type command struct {
	name            string
	params          []string
	successResponse bool
	run             handler
}

// commands is the allow-list, in the order guest-info reports it.
var commands = []command{
	{name: "guest-sync", params: []string{"id"}, successResponse: true, run: cmdSync},
	{name: "guest-sync-delimited", params: []string{"id"}, successResponse: true, run: cmdSyncDelimited},
	{name: "guest-ping", successResponse: true, run: cmdPing},
	{name: "guest-info", successResponse: true, run: cmdInfo},
	{name: "guest-get-osinfo", successResponse: true, run: cmdOSInfo},
	{name: "guest-get-host-name", successResponse: true, run: cmdHostName},
	{name: "guest-get-time", successResponse: true, run: cmdTime},
	{name: "guest-get-timezone", successResponse: true, run: cmdTimezone},
	{name: "guest-network-get-interfaces", successResponse: true, run: cmdInterfaces},
	{name: "guest-shutdown", params: []string{"mode"}, successResponse: false, run: cmdShutdown},
	{name: "guest-fsfreeze-status", successResponse: true, run: cmdFsfreezeStatus},
}

// refused lists qemu-ga commands this agent never runs. They answer with the
// "has been disabled" error a qemu-ga started with --block-rpcs sends; any
// other name is "not found". Their arguments are never decoded or logged.
var refused = map[string]bool{
	"guest-exec": true, "guest-exec-status": true,
	"guest-file-open": true, "guest-file-close": true, "guest-file-read": true, "guest-file-write": true,
	"guest-file-seek": true, "guest-file-flush": true,
	"guest-set-user-password":       true,
	"guest-ssh-get-authorized-keys": true, "guest-ssh-add-authorized-keys": true, "guest-ssh-remove-authorized-keys": true,
	"guest-fsfreeze-freeze": true, "guest-fsfreeze-freeze-list": true, "guest-fsfreeze-thaw": true,
	"guest-fstrim": true, "guest-set-time": true,
	"guest-suspend-disk": true, "guest-suspend-ram": true, "guest-suspend-hybrid": true,
	"guest-get-vcpus": true, "guest-set-vcpus": true,
	"guest-get-memory-blocks": true, "guest-set-memory-blocks": true, "guest-get-memory-block-info": true,
	"guest-get-disks": true, "guest-get-fsinfo": true, "guest-get-users": true, "guest-get-devices": true,
	"guest-get-diskstats": true, "guest-get-cpustats": true, "guest-get-load": true,
	"guest-network-get-route": true,
}

var byName = func() map[string]command {
	m := make(map[string]command, len(commands))
	for _, c := range commands {
		m[c.name] = c
	}

	return m
}()

// session holds the parser state for one host connection and writes the
// responses to w.
type session struct {
	host Host
	w    io.Writer
	logf func(format string, args ...any)
	sc   scanner
}

func newSession(h Host, w io.Writer, logf func(format string, args ...any)) *session {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	return &session{host: h, w: w, logf: logf}
}

// feed consumes bytes read from the port.
func (s *session) feed(p []byte) {
	for _, b := range p {
		pending := s.sc.pending()
		if s.sc.push(b, s.handle) {
			if pending > 0 {
				s.logf("qga: resync from the host; dropped %d bytes of a partial request", pending)
			} else {
				s.logf("qga: resync from the host")
			}
		}
	}
}

// reset drops any partial request, as when the host goes away mid-request.
func (s *session) reset() {
	if n := s.sc.pending(); n > 0 {
		s.logf("qga: dropped %d bytes of a partial request", n)
	}
	s.sc.reset()
}

func (s *session) handle(ev scanEvent) {
	switch ev.kind {
	case eventTooLarge:
		s.logf("qga: refused a request over %d bytes (%d bytes skipped)", maxRequestBytes, ev.dropped)
		s.write(response{Error: generic("JSON request too large (limit %d bytes)", maxRequestBytes)}, false)
	case eventTooDeep:
		s.logf("qga: refused a request nested deeper than %d levels (%d bytes)", maxDepth, ev.dropped)
		s.write(response{Error: generic("JSON request nested too deeply (limit %d)", maxDepth)}, false)
	case eventScalar:
		if json.Valid(ev.msg) {
			s.logf("qga: refused a request that is not a JSON object (%d bytes)", len(ev.msg))
			s.write(response{Error: generic("QMP input must be a JSON object")}, false)

			return
		}
		s.logf("qga: JSON parse error (%d bytes)", len(ev.msg))
		s.write(response{Error: generic("JSON parse error, invalid token")}, false)
	case eventObject:
		s.dispatch(ev.msg)
	}
}

func (s *session) dispatch(raw []byte) {
	start := time.Now()
	if !json.Valid(raw) {
		s.logf("qga: JSON parse error (%d bytes)", len(raw))
		s.write(response{Error: generic("JSON parse error, invalid syntax")}, false)

		return
	}
	if bytes.TrimSpace(raw)[0] != '{' {
		s.logf("qga: refused a request that is not a JSON object (%d bytes)", len(raw))
		s.write(response{Error: generic("QMP input must be a JSON object")}, false)

		return
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		s.logf("qga: JSON parse error: %v", err)
		s.write(response{Error: generic("JSON parse error, %v", err)}, false)

		return
	}
	id := top["id"]
	fail := func(name string, e *qerror) {
		s.logf("qga: %s%s refused: %s (%s)", name, idNote(id), e.Desc, time.Since(start))
		s.write(response{Error: e, ID: id}, false)
	}
	for _, k := range sortedKeys(top) {
		if k != "execute" && k != "arguments" && k != "id" {
			fail("request", generic("QMP input member '%s' is unexpected", k))

			return
		}
	}
	execRaw, ok := top["execute"]
	if !ok {
		fail("request", generic("QMP input lacks member 'execute'"))

		return
	}
	var name string
	if err := json.Unmarshal(execRaw, &name); err != nil {
		fail("request", generic("QMP input member 'execute' must be a string"))

		return
	}
	cmd, ok := byName[name]
	if !ok {
		e := &qerror{Class: classCommandNotFound, Desc: fmt.Sprintf("The command %s has not been found", name)}
		if refused[name] {
			e.Desc = fmt.Sprintf("Command %s has been disabled", name)
			s.logf("qga: %s%s refused by policy (not on the allow-list)", name, idNote(id))
		} else {
			s.logf("qga: %s%s unknown command", name, idNote(id))
		}
		s.write(response{Error: e, ID: id}, false)

		return
	}
	args, qe := decodeArgs(top["arguments"], cmd.params)
	if qe != nil {
		fail(name, qe)

		return
	}
	s.logf("qga: %s%s received", name, idNote(id))
	res := cmd.run(s, args)
	switch {
	case res.err != nil:
		fail(name, res.err)
	case res.noResponse:
		s.logf("qga: %s%s done, no response by protocol (%s)", name, idNote(id), time.Since(start))
	default:
		s.write(response{Return: res.value, ID: id}, res.delimited)
		s.logf("qga: %s%s ok (%s)", name, idNote(id), time.Since(start))
	}
}

// decodeArgs checks "arguments" is absent, null or an object holding only
// the named parameters.
func decodeArgs(raw json.RawMessage, params []string) (map[string]json.RawMessage, *qerror) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return map[string]json.RawMessage{}, nil
	}
	if t[0] != '{' {
		return nil, generic("QMP input member 'arguments' must be an object")
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(t, &args); err != nil {
		return nil, generic("QMP input member 'arguments' must be an object")
	}
	allowed := make(map[string]bool, len(params))
	for _, p := range params {
		allowed[p] = true
	}
	for _, k := range sortedKeys(args) {
		if !allowed[k] {
			return nil, generic("Parameter '%s' is unexpected", k)
		}
	}

	return args, nil
}

// write sends one response line, after the 0xFF delimiter when asked. A
// failed write (the host went away) is logged and dropped.
func (s *session) write(r response, delimited bool) {
	b, err := json.Marshal(r)
	if err != nil {
		s.logf("qga: encode response: %v", err)

		return
	}
	out := make([]byte, 0, len(b)+2)
	if delimited {
		out = append(out, resyncByte)
	}
	out = append(out, b...)
	out = append(out, '\n')
	if _, err := s.w.Write(out); err != nil {
		s.logf("qga: write response: %v", err)
	}
}

func idNote(id json.RawMessage) string {
	if len(id) == 0 {
		return ""
	}

	return " id=" + string(id)
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}
