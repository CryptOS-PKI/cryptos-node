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
	"encoding/json"
	"strconv"
)

func syncID(args map[string]json.RawMessage) (int64, *qerror) {
	raw, ok := args["id"]
	if !ok {
		return 0, generic("Parameter 'id' is missing")
	}
	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, generic("Invalid parameter type for 'id', expected: integer")
	}

	return id, nil
}

func cmdSync(_ *session, args map[string]json.RawMessage) result {
	id, qe := syncID(args)
	if qe != nil {
		return result{err: qe}
	}

	return result{value: id}
}

func cmdSyncDelimited(_ *session, args map[string]json.RawMessage) result {
	id, qe := syncID(args)
	if qe != nil {
		return result{err: qe}
	}

	return result{value: id, delimited: true}
}

func cmdPing(*session, map[string]json.RawMessage) result {
	return result{value: struct{}{}}
}

type commandInfo struct {
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	SuccessResponse bool   `json:"success-response"`
}

// supportedCommands is guest-info's list, built from the allow-list once it
// exists (cmdInfo is itself on the allow-list).
var supportedCommands []commandInfo

func init() {
	for _, c := range commands {
		supportedCommands = append(supportedCommands, commandInfo{Name: c.name, Enabled: true, SuccessResponse: c.successResponse})
	}
}

func cmdInfo(s *session, _ map[string]json.RawMessage) result {
	return result{value: struct {
		Version  string        `json:"version"`
		Commands []commandInfo `json:"supported_commands"`
	}{Version: s.host.Version(), Commands: supportedCommands}}
}

func cmdOSInfo(s *session, _ map[string]json.RawMessage) result {
	u, err := s.host.Uname()
	if err != nil {
		return result{err: generic("%v", err)}
	}
	v := s.host.Version()

	return result{value: struct {
		KernelRelease string `json:"kernel-release"`
		KernelVersion string `json:"kernel-version"`
		Machine       string `json:"machine"`
		ID            string `json:"id"`
		Name          string `json:"name"`
		PrettyName    string `json:"pretty-name"`
		Version       string `json:"version"`
		VersionID     string `json:"version-id"`
	}{
		KernelRelease: u.Release, KernelVersion: u.Version, Machine: u.Machine,
		ID: "cryptos", Name: "CryptOS", PrettyName: "CryptOS " + v, Version: v, VersionID: v,
	}}
}

func cmdHostName(s *session, _ map[string]json.RawMessage) result {
	name, err := s.host.HostName()
	if err != nil {
		return result{err: generic("%v", err)}
	}

	return result{value: struct {
		HostName string `json:"host-name"`
	}{name}}
}

func cmdTime(s *session, _ map[string]json.RawMessage) result {
	return result{value: s.host.Now().UnixNano()}
}

func cmdTimezone(s *session, _ map[string]json.RawMessage) result {
	zone, offset := s.host.Now().Zone()

	return result{value: struct {
		Zone   string `json:"zone,omitempty"`
		Offset int    `json:"offset"`
	}{zone, offset}}
}

func cmdInterfaces(s *session, _ map[string]json.RawMessage) result {
	ifs, err := s.host.Interfaces()
	if err != nil {
		return result{err: generic("%v", err)}
	}
	if ifs == nil {
		ifs = []Interface{}
	}

	return result{value: ifs}
}

func cmdShutdown(s *session, args map[string]json.RawMessage) result {
	mode := "powerdown"
	if raw, ok := args["mode"]; ok {
		if err := json.Unmarshal(raw, &mode); err != nil {
			return result{err: generic("Parameter 'mode' must be a string")}
		}
	}
	switch mode {
	case "powerdown", "halt", "reboot":
	default:
		return result{err: generic("Parameter 'mode' expects 'powerdown', 'halt' or 'reboot'")}
	}
	s.logf("qga: guest-shutdown mode=%s; asking the node for an orderly stop", mode)
	if err := s.host.Shutdown(mode); err != nil {
		return result{err: generic("%v", err)}
	}

	return result{noResponse: true}
}

func cmdFsfreezeStatus(*session, map[string]json.RawMessage) result {
	return result{value: "thawed"}
}
