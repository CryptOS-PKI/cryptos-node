package grpc

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
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

func TestNewLocal_UnixSocketRoundTrip(t *testing.T) {
	auditor := &mockAuditor{}
	srv, err := NewLocal(ServerConfig{
		Auditor: auditor,
		Status:  &mockStatus{resp: &nodev1.NodeStatus{BootCount: 5, Role: nodev1.NodeRole_NODE_ROLE_ROOT}},
		Identity: &mockIdentity{resp: &nodev1.Identity{
			ChainPem: "x", LeafSha256: []byte{1},
		}},
		Ceremony:    &mockCeremony{},
		ConfigStore: &mockConfigStore{resp: &nodev1.ApplyConfigResponse{}},
	})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}

	sockPath := shortSockPath(t)
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("unix:"+sockPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := nodev1.NewNodeServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetStatus(ctx, &nodev1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus over unix socket: %v", err)
	}
	if resp.Status.BootCount != 5 {
		t.Errorf("BootCount = %d, want 5", resp.Status.BootCount)
	}

	// A state-changing local call is audited; actor_subject is empty for
	// the no-TLS local socket.
	if _, err := client.ApplyConfig(ctx, &nodev1.ApplyConfigRequest{Config: &nodev1.MachineConfig{}}); err != nil {
		t.Fatalf("ApplyConfig over unix socket: %v", err)
	}
	if got := auditor.snapshot(); len(got) != 1 {
		t.Errorf("local audit entries = %v, want one for ApplyConfig", got)
	} else if got[0].ActorSubject != "" {
		t.Errorf("actor_subject = %q, want empty for local socket", got[0].ActorSubject)
	}
}

func TestNewLocal_RequiresAuditor(t *testing.T) {
	if _, err := NewLocal(ServerConfig{}); err == nil {
		t.Fatal("NewLocal without Auditor = nil, want error")
	}
}
