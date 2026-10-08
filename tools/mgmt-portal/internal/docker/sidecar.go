package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/errdefs"
)

// PcapSidecarSuffix is the name suffix of the tcpdump sidecar that every NF
// runs with network_mode "service:<nf>" (docker-compose.yml).
const PcapSidecarSuffix = "-pcap"

// sidecarRestartTimeout is the stop grace period (seconds) used when
// restarting a netns sidecar; tcpdump exits promptly on SIGTERM.
const sidecarRestartTimeout = 5

// sidecarAPI is the subset of the Docker SDK used by sidecar recovery. It is
// satisfied by *client.Client and faked in unit tests.
type sidecarAPI interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerRestart(ctx context.Context, containerID string, options container.StopOptions) error
}

// RestartNetnsSidecars restarts the sidecar container "<name>-pcap" when it
// shares name's network namespace (HostConfig.NetworkMode "container:<id>").
//
// A container joined to another container's netns stays attached to the old,
// dead namespace when that container is restarted, so capture silently stops;
// restarting the sidecar re-joins it to the current namespace. Call it after
// name is running again (after Restart or Start). A missing sidecar, or name
// being a sidecar itself, is a no-op. It returns the sidecars restarted and,
// per sidecar name, the errors hit while inspecting or restarting it.
func (c *Client) RestartNetnsSidecars(ctx context.Context, name string) ([]string, map[string]error) {
	return restartNetnsSidecars(ctx, c.cli, name)
}

func restartNetnsSidecars(ctx context.Context, api sidecarAPI, name string) ([]string, map[string]error) {
	if name == "" || strings.HasSuffix(name, PcapSidecarSuffix) {
		return nil, nil
	}
	sidecar := name + PcapSidecarSuffix
	sc, err := api.ContainerInspect(ctx, sidecar)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, nil
		}
		return nil, map[string]error{sidecar: fmt.Errorf("docker: inspect sidecar %s: %w", sidecar, err)}
	}
	if sc.HostConfig == nil {
		return nil, nil
	}
	mode := string(sc.HostConfig.NetworkMode)
	if !strings.HasPrefix(mode, "container:") && !strings.HasPrefix(mode, "service:") {
		return nil, nil
	}
	nf, err := api.ContainerInspect(ctx, name)
	if err != nil {
		return nil, map[string]error{sidecar: fmt.Errorf("docker: inspect %s: %w", name, err)}
	}
	if !sharesNetns(mode, name, nf) {
		return nil, nil
	}
	timeout := sidecarRestartTimeout
	if err := api.ContainerRestart(ctx, sidecar, container.StopOptions{Timeout: &timeout}); err != nil {
		return nil, map[string]error{sidecar: fmt.Errorf("docker: restart sidecar %s: %w", sidecar, err)}
	}
	return []string{sidecar}, nil
}

// sharesNetns reports whether a NetworkMode value ("container:<id|name>" or
// "service:<name>") points at the container nf (named name).
func sharesNetns(mode, name string, nf types.ContainerJSON) bool {
	target := mode
	if i := strings.IndexByte(mode, ':'); i >= 0 {
		target = mode[i+1:]
	}
	if target == "" {
		return false
	}
	if target == name {
		return true
	}
	if nf.ContainerJSONBase == nil {
		return false
	}
	if strings.TrimPrefix(nf.Name, "/") == target {
		return true
	}
	// Docker stores the full 64-hex id; accept a short-id prefix as well.
	return len(target) >= 12 && strings.HasPrefix(nf.ID, target)
}
