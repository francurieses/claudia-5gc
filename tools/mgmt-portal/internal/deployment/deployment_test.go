package deployment

import (
	"context"
	"errors"
	"testing"
	"time"

	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

func svc(name, state string) dockerclient.Service {
	return dockerclient.Service{Name: name, State: state}
}

func TestDetect(t *testing.T) {
	now := time.Unix(1000, 0)
	core := []dockerclient.Service{svc("amf", "running"), svc("smf", "running")}
	tests := []struct {
		name         string
		services     []dockerclient.Service
		override     string
		wantMode     string
		wantSource   string
		wantUERANSIM bool
		wantPR       bool
		wantURunning bool
	}{
		{"standalone", core, "", ModeStandalone, SourceDocker, false, false, false},
		{"ueransim running", append(append([]dockerclient.Service{}, core...), svc("ueransim-gnb", "running"), svc("ueransim-ue", "running")),
			"auto", ModeUERANSIM, SourceDocker, true, false, true},
		{"ueransim created only", append(append([]dockerclient.Service{}, core...), svc("ueransim-gnb", "created")),
			"", ModeUERANSIM, SourceDocker, true, false, false},
		{"packetrusher only", append(append([]dockerclient.Service{}, core...), svc("packetrusher-n2", "exited")),
			"", ModePacketRusher, SourceDocker, false, true, false},
		{"both", append(append([]dockerclient.Service{}, core...), svc("ueransim-gnb", "running"), svc("packetrusher", "created")),
			"", ModeBoth, SourceDocker, true, true, true},
		{"override none hides existing", append(append([]dockerclient.Service{}, core...), svc("ueransim-gnb", "running")),
			"none", ModeStandalone, SourceOverride, false, false, true},
		{"override both with nothing deployed", core, "both", ModeBoth, SourceOverride, true, true, false},
		{"leading slash in name", []dockerclient.Service{svc("/ueransim-gnb", "running")},
			"", ModeUERANSIM, SourceDocker, true, false, true},
		{"unrelated name not matched", []dockerclient.Service{svc("ueransim", "running"), svc("packetrusher-x", "running")},
			"", ModeStandalone, SourceDocker, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Detect(tt.services, tt.override, now)
			if c.Mode != tt.wantMode || c.Source != tt.wantSource {
				t.Fatalf("mode/source = %s/%s, want %s/%s", c.Mode, c.Source, tt.wantMode, tt.wantSource)
			}
			if c.UERANSIM.Deployed != tt.wantUERANSIM || c.PacketRusher.Deployed != tt.wantPR {
				t.Errorf("deployed = %v/%v, want %v/%v", c.UERANSIM.Deployed, c.PacketRusher.Deployed, tt.wantUERANSIM, tt.wantPR)
			}
			if c.UERANSIM.Running != tt.wantURunning {
				t.Errorf("ueransim running = %v, want %v", c.UERANSIM.Running, tt.wantURunning)
			}
			if c.UERANSIM.Containers == nil || c.PacketRusher.Containers == nil {
				t.Error("container lists must be non-nil for JSON")
			}
		})
	}
}

type fakeLister struct {
	calls int
	svcs  []dockerclient.Service
	err   error
}

func (f *fakeLister) List(context.Context) ([]dockerclient.Service, error) {
	f.calls++
	return f.svcs, f.err
}

func TestDetector_CachesFor5Seconds(t *testing.T) {
	l := &fakeLister{svcs: []dockerclient.Service{svc("ueransim-gnb", "running")}}
	d := NewDetector(l, "")
	clock := time.Unix(1000, 0)
	d.now = func() time.Time { return clock }

	if m := d.Get(context.Background()).Mode; m != ModeUERANSIM {
		t.Fatalf("mode = %s", m)
	}
	l.svcs = nil
	clock = clock.Add(2 * time.Second)
	if m := d.Get(context.Background()).Mode; m != ModeUERANSIM || l.calls != 1 {
		t.Fatalf("within TTL: mode=%s calls=%d, want cached", m, l.calls)
	}
	clock = clock.Add(4 * time.Second)
	if m := d.Get(context.Background()).Mode; m != ModeStandalone || l.calls != 2 {
		t.Fatalf("after TTL: mode=%s calls=%d, want re-probe", m, l.calls)
	}
}

func TestDetector_NilDockerFallsBackToStandalone(t *testing.T) {
	c := NewDetector(nil, "").Get(context.Background())
	if c.Mode != ModeStandalone || c.Source != SourceUnavailable {
		t.Fatalf("caps = %+v", c)
	}
	c = NewDetector(nil, "ueransim").Get(context.Background())
	if c.Mode != ModeUERANSIM || c.Source != SourceOverride {
		t.Fatalf("override caps = %+v", c)
	}
}

func TestDetector_DockerErrorIsUnavailable(t *testing.T) {
	c := NewDetector(&fakeLister{err: errors.New("boom")}, "").Get(context.Background())
	if c.Mode != ModeStandalone || c.Source != SourceUnavailable {
		t.Fatalf("caps = %+v", c)
	}
}

func TestCapabilitiesHas(t *testing.T) {
	c := Detect([]dockerclient.Service{svc("packetrusher", "created")}, "", time.Now())
	if c.Has("ueransim") || !c.Has("packetrusher") || c.Has("other") {
		t.Errorf("Has = %v/%v", c.Has("ueransim"), c.Has("packetrusher"))
	}
}
