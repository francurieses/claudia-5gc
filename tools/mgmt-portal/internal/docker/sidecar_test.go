package docker

import (
	"context"
	"errors"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/errdefs"
)

const nfID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeSidecarAPI struct {
	containers map[string]types.ContainerJSON
	restartErr error
	restarted  []string
}

func (f *fakeSidecarAPI) ContainerInspect(_ context.Context, id string) (types.ContainerJSON, error) {
	c, ok := f.containers[id]
	if !ok {
		return types.ContainerJSON{}, errdefs.NotFound(errors.New("no such container: " + id))
	}
	return c, nil
}

func (f *fakeSidecarAPI) ContainerRestart(_ context.Context, id string, _ container.StopOptions) error {
	if f.restartErr != nil {
		return f.restartErr
	}
	f.restarted = append(f.restarted, id)
	return nil
}

func ctr(id, name, netMode string) types.ContainerJSON {
	return types.ContainerJSON{ContainerJSONBase: &types.ContainerJSONBase{
		ID:         id,
		Name:       "/" + name,
		HostConfig: &container.HostConfig{NetworkMode: container.NetworkMode(netMode)},
	}}
}

func TestRestartNetnsSidecars(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		containers  map[string]types.ContainerJSON
		restartErr  error
		wantRestart []string
		wantErrKey  string
	}{
		{
			name:   "sidecar joined by container id is restarted",
			target: "amf",
			containers: map[string]types.ContainerJSON{
				"amf":      ctr(nfID, "amf", "5gc-rel17_sbi"),
				"amf-pcap": ctr("ffff", "amf-pcap", "container:"+nfID),
			},
			wantRestart: []string{"amf-pcap"},
		},
		{
			name:   "sidecar joined by service name is restarted",
			target: "smf",
			containers: map[string]types.ContainerJSON{
				"smf":      ctr(nfID, "smf", "bridge"),
				"smf-pcap": ctr("ffff", "smf-pcap", "service:smf"),
			},
			wantRestart: []string{"smf-pcap"},
		},
		{
			name:       "no sidecar is a no-op",
			target:     "nrf",
			containers: map[string]types.ContainerJSON{"nrf": ctr(nfID, "nrf", "bridge")},
		},
		{
			name:   "sidecar on its own network is left alone",
			target: "udm",
			containers: map[string]types.ContainerJSON{
				"udm":      ctr(nfID, "udm", "bridge"),
				"udm-pcap": ctr("ffff", "udm-pcap", "bridge"),
			},
		},
		{
			name:   "sidecar joined to a different container is left alone",
			target: "udr",
			containers: map[string]types.ContainerJSON{
				"udr":      ctr(nfID, "udr", "bridge"),
				"udr-pcap": ctr("ffff", "udr-pcap", "container:fedcba9876543210fedcba9876543210"),
			},
		},
		{
			name:   "restarting a sidecar directly does not recurse",
			target: "amf-pcap",
			containers: map[string]types.ContainerJSON{
				"amf-pcap":      ctr("ffff", "amf-pcap", "container:"+nfID),
				"amf-pcap-pcap": ctr("eeee", "amf-pcap-pcap", "container:ffff"),
			},
		},
		{
			name:   "sidecar restart error is reported",
			target: "upf",
			containers: map[string]types.ContainerJSON{
				"upf":      ctr(nfID, "upf", "bridge"),
				"upf-pcap": ctr("ffff", "upf-pcap", "container:"+nfID),
			},
			restartErr: errors.New("boom"),
			wantErrKey: "upf-pcap",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeSidecarAPI{containers: tc.containers, restartErr: tc.restartErr}
			got, errs := restartNetnsSidecars(context.Background(), api, tc.target)
			if len(got) != len(tc.wantRestart) || (len(got) > 0 && got[0] != tc.wantRestart[0]) {
				t.Fatalf("restarted = %v, want %v", got, tc.wantRestart)
			}
			if len(api.restarted) != len(tc.wantRestart) {
				t.Fatalf("ContainerRestart calls = %v, want %v", api.restarted, tc.wantRestart)
			}
			if tc.wantErrKey == "" && len(errs) != 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if tc.wantErrKey != "" && errs[tc.wantErrKey] == nil {
				t.Fatalf("errors = %v, want key %q", errs, tc.wantErrKey)
			}
		})
	}
}
