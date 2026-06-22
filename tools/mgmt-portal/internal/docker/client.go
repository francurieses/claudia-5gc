package docker

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	dockernetwork "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// Service represents a Docker container managed by the portal.
type Service struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	Status  string `json:"status"`
	State   string `json:"state"`
	Created int64  `json:"created"`
	Uptime  string `json:"uptime"`
}

// ExecResult holds the output of a container exec operation.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

// Client wraps the Docker SDK client.
type Client struct {
	cli *client.Client
}

// New returns a Client connected to the local Docker daemon.
func New() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Client{cli: cli}, nil
}

// Close closes the underlying Docker client.
func (c *Client) Close() { c.cli.Close() }

// List returns all containers belonging to the 5gc-rel17 compose project.
func (c *Client) List(ctx context.Context) ([]Service, error) {
	f := filters.NewArgs(filters.Arg("label", "com.docker.compose.project=5gc-rel17"))
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: f,
	})
	if err != nil {
		return nil, err
	}

	svcs := make([]Service, 0, len(containers))
	for _, ctr := range containers {
		name := strings.TrimPrefix(ctr.Names[0], "/")
		uptime := ""
		if ctr.State == "running" {
			d := time.Since(time.Unix(ctr.Created, 0))
			uptime = formatDuration(d)
		}
		svcs = append(svcs, Service{
			ID:      ctr.ID[:12],
			Name:    name,
			Image:   ctr.Image,
			Status:  ctr.Status,
			State:   ctr.State,
			Created: ctr.Created,
			Uptime:  uptime,
		})
	}
	return svcs, nil
}

// Start starts a container by name.
func (c *Client) Start(ctx context.Context, name string) error {
	return c.cli.ContainerStart(ctx, name, container.StartOptions{})
}

// Stop stops a container by name with a 10 s grace period.
func (c *Client) Stop(ctx context.Context, name string) error {
	timeout := 10
	return c.cli.ContainerStop(ctx, name, container.StopOptions{Timeout: &timeout})
}

// Restart restarts a container by name.
func (c *Client) Restart(ctx context.Context, name string) error {
	timeout := 10
	return c.cli.ContainerRestart(ctx, name, container.StopOptions{Timeout: &timeout})
}

// Pause sends SIGSTOP to all processes in the container.
func (c *Client) Pause(ctx context.Context, name string) error {
	return c.cli.ContainerPause(ctx, name)
}

// Unpause resumes a paused container.
func (c *Client) Unpause(ctx context.Context, name string) error {
	return c.cli.ContainerUnpause(ctx, name)
}

// Logs returns a ReadCloser streaming logs for the given container.
// tail = number of last lines to include ("all" for everything).
func (c *Client) Logs(ctx context.Context, name, tail string) (io.ReadCloser, error) {
	return c.cli.ContainerLogs(ctx, name, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       tail,
		Timestamps: false,
	})
}

// Inspect returns low-level container info.
func (c *Client) Inspect(ctx context.Context, name string) (types.ContainerJSON, error) {
	return c.cli.ContainerInspect(ctx, name)
}

// Exec runs a command inside a running container and returns its combined stdout+stderr.
// It respects context cancellation: if ctx is cancelled while the command is running,
// Exec closes the hijacked connection and returns ctx.Err() promptly.
func (c *Client) Exec(ctx context.Context, containerName string, cmd []string) (ExecResult, error) {
	id, err := c.cli.ContainerExecCreate(ctx, containerName, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return ExecResult{}, err
	}

	resp, err := c.cli.ContainerExecAttach(ctx, id.ID, container.ExecStartOptions{})
	if err != nil {
		return ExecResult{}, err
	}
	defer resp.Close()

	type copyResult struct {
		stdout bytes.Buffer
		stderr bytes.Buffer
		err    error
	}
	ch := make(chan copyResult, 1)
	go func() {
		var r copyResult
		_, r.err = stdcopy.StdCopy(&r.stdout, &r.stderr, resp.Reader)
		ch <- r
	}()

	select {
	case <-ctx.Done():
		// Close the hijacked connection to unblock the reader goroutine.
		resp.Close()
		return ExecResult{}, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return ExecResult{}, r.err
		}
		// Use a fresh context for the inspect call — the original may be cancelled.
		insp, err := c.cli.ContainerExecInspect(context.Background(), id.ID)
		if err != nil {
			return ExecResult{}, err
		}
		combined := r.stdout.String()
		if s := r.stderr.String(); s != "" {
			combined += s
		}
		return ExecResult{ExitCode: insp.ExitCode, Output: combined}, nil
	}
}

// CreateNetwork creates a Docker bridge network with the given name and subnet CIDR.
func (c *Client) CreateNetwork(ctx context.Context, networkName, subnet string) error {
	_, err := c.cli.NetworkCreate(ctx, networkName, dockernetwork.CreateOptions{
		Driver: "bridge",
		IPAM: &dockernetwork.IPAM{
			Config: []dockernetwork.IPAMConfig{{Subnet: subnet}},
		},
	})
	return err
}

// RemoveNetwork removes a Docker network by name or ID.
func (c *Client) RemoveNetwork(ctx context.Context, networkName string) error {
	return c.cli.NetworkRemove(ctx, networkName)
}

// ConnectToNetwork attaches a running container to a Docker network.
func (c *Client) ConnectToNetwork(ctx context.Context, containerName, networkName string) error {
	return c.cli.NetworkConnect(ctx, networkName, containerName, nil)
}

// DisconnectFromNetwork detaches a container from a Docker network.
func (c *Client) DisconnectFromNetwork(ctx context.Context, containerName, networkName string) error {
	return c.cli.NetworkDisconnect(ctx, networkName, containerName, false)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return d.String()
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return formatParts(m, "m", s, "s")
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return formatParts(h, "h", m, "m")
}

func formatParts(a int, au string, b int, bu string) string {
	if b == 0 {
		return itoa(a) + au
	}
	return itoa(a) + au + itoa(b) + bu
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
