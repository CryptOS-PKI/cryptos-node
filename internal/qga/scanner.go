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

const (
	// maxRequestBytes caps one request. The largest request the allow-list
	// takes is well under 1 KiB; qemu-ga's own lexer allows far more, but
	// nothing this agent answers needs it.
	maxRequestBytes = 64 << 10
	// maxDepth caps object and array nesting in one request.
	maxDepth = 32
	// resyncByte is the QGA delimiter: from the host it resets the parser,
	// and guest-sync-delimited writes it before its response.
	resyncByte = 0xFF
)

type eventKind int

const (
	// eventObject is one complete top-level object or array.
	eventObject eventKind = iota
	// eventScalar is top-level input that is not an object or array.
	eventScalar
	// eventTooLarge is a request over maxRequestBytes, already skipped.
	eventTooLarge
	// eventTooDeep is a request nested deeper than maxDepth.
	eventTooDeep
)

// scanEvent is one finished unit of input. msg is only valid until the next
// push.
type scanEvent struct {
	kind    eventKind
	msg     []byte
	dropped int
}

// scanner splits a QGA input stream into top-level JSON values. QGA does not
// require newlines between requests (qemu-ga uses a streaming parser), so it
// tracks brace depth and string state instead of splitting on lines. It never
// decodes anything; the session does that once a value is complete.
type scanner struct {
	buf       []byte
	depth     int
	inStr     bool
	esc       bool
	scalar    bool
	oversized bool
	tooDeep   bool
	dropped   int
}

// pending is the number of bytes of an unfinished request.
func (s *scanner) pending() int {
	return len(s.buf) + s.dropped
}

// reset discards any unfinished request.
func (s *scanner) reset() {
	*s = scanner{buf: s.buf[:0]}
}

// push consumes one byte, calling emit for every value it completes. It
// returns true when the byte was a resync (0xFF).
func (s *scanner) push(b byte, emit func(scanEvent)) bool {
	if b == resyncByte {
		s.reset()

		return true
	}
	if s.scalar {
		if !isSpace(b) && b != '{' && b != '[' {
			s.add(b)

			return false
		}
		s.finish(eventScalar, emit)
		if isSpace(b) {
			return false
		}
	}
	if s.depth == 0 {
		switch {
		case isSpace(b):
		case b == '{' || b == '[':
			s.depth = 1
			s.add(b)
		default:
			s.scalar = true
			s.add(b)
		}

		return false
	}
	s.add(b)
	if s.inStr {
		switch {
		case s.esc:
			s.esc = false
		case b == '\\':
			s.esc = true
		case b == '"':
			s.inStr = false
		}

		return false
	}
	switch b {
	case '"':
		s.inStr = true
	case '{', '[':
		s.depth++
		if s.depth > maxDepth {
			s.tooDeep = true
		}
	case '}', ']':
		s.depth--
		if s.depth == 0 {
			s.finish(eventObject, emit)
		}
	}

	return false
}

// add appends b, switching to skip mode (counting, not storing) once the
// request passes maxRequestBytes.
func (s *scanner) add(b byte) {
	if s.oversized {
		s.dropped++

		return
	}
	if len(s.buf) >= maxRequestBytes {
		s.oversized = true
		s.dropped = len(s.buf) + 1
		s.buf = s.buf[:0]

		return
	}
	s.buf = append(s.buf, b)
}

// finish emits the value just completed and clears the state for the next.
func (s *scanner) finish(kind eventKind, emit func(scanEvent)) {
	ev := scanEvent{kind: kind, msg: s.buf}
	switch {
	case s.oversized:
		ev = scanEvent{kind: eventTooLarge, dropped: s.dropped}
	case s.tooDeep:
		ev = scanEvent{kind: eventTooDeep, dropped: len(s.buf)}
	}
	emit(ev)
	s.reset()
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}
