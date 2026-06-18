// Package ueransim wraps docker exec calls to the UERANSIM container.
// The Client interface keeps tool handlers free of exec details and enables
// unit testing via MockClient without a running Docker daemon.
package ueransim

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// UEStatus captures nr-cli STATUS output for one UE.
type UEStatus struct {
	SUPI        string
	MMState     string // e.g. MM-REGISTERED, MM-DEREGISTERED
	CMState     string // e.g. CM-CONNECTED, CM-IDLE
	Registered  bool
}

// PDUSession carries the result of a PDU session establishment.
type PDUSession struct {
	SessionID int
	UEAddr    string // UE IP assigned
	DNNName   string
}

// ContainerInfo reports the container-level health of the UERANSIM UE process.
type ContainerInfo struct {
	Running         bool
	RegisteredSUPIs []string
	ActiveSessions  int
	UptimeSeconds   int
}

// Client abstracts UERANSIM control so Group F tools are testable.
type Client interface {
	UEStatus(ctx context.Context, supi string) (*UEStatus, error)
	PDUSessionEstablish(ctx context.Context, supi, dnn string) (*PDUSession, error)
	PDUSessionRelease(ctx context.Context, supi string, sessionID int) error
	Deregister(ctx context.Context, supi string) error
	ContainerInfo(ctx context.Context) (*ContainerInfo, error)
}

// DockerClient calls nr-cli via `docker exec <container> nr-cli …`.
type DockerClient struct {
	container string
	timeout   time.Duration
	log       *slog.Logger
}

// NewDockerClient returns a client targeting the named container.
func NewDockerClient(container string, timeout time.Duration, log *slog.Logger) *DockerClient {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &DockerClient{container: container, timeout: timeout, log: log}
}

func (c *DockerClient) exec(ctx context.Context, args ...string) (string, error) {
	tCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(tCtx, "docker", append([]string{"exec", c.container}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	c.log.InfoContext(ctx, "ueransim exec",
		"container", c.container,
		"command", strings.Join(args, " "),
		"duration_ms", time.Since(start).Milliseconds(),
		"exit_code", exitCode(err),
	)
	if err != nil {
		return "", fmt.Errorf("docker exec %s: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// UEStatus returns the current GMM/CM state for a SUPI.
func (c *DockerClient) UEStatus(ctx context.Context, supi string) (*UEStatus, error) {
	out, err := c.exec(ctx, "nr-cli", supi, "-e", "STATUS")
	if err != nil {
		return nil, fmt.Errorf("ueransim: STATUS %s: %w", supi, err)
	}
	return parseStatus(supi, out), nil
}

// PDUSessionEstablish triggers a PDU session for the UE.
func (c *DockerClient) PDUSessionEstablish(ctx context.Context, supi, dnn string) (*PDUSession, error) {
	cmd := fmt.Sprintf("ps-establish default %s", dnn)
	out, err := c.exec(ctx, "nr-cli", supi, "-e", cmd)
	if err != nil {
		return nil, fmt.Errorf("ueransim: ps-establish %s %s: %w", supi, dnn, err)
	}
	return parsePDUSession(out), nil
}

// PDUSessionRelease releases a specific PDU session.
func (c *DockerClient) PDUSessionRelease(ctx context.Context, supi string, sessionID int) error {
	cmd := fmt.Sprintf("ps-release %d", sessionID)
	_, err := c.exec(ctx, "nr-cli", supi, "-e", cmd)
	if err != nil {
		return fmt.Errorf("ueransim: ps-release %s %d: %w", supi, sessionID, err)
	}
	return nil
}

// Deregister triggers UE-initiated deregistration.
func (c *DockerClient) Deregister(ctx context.Context, supi string) error {
	_, err := c.exec(ctx, "nr-cli", supi, "-e", "deregister normal")
	if err != nil {
		return fmt.Errorf("ueransim: deregister %s: %w", supi, err)
	}
	return nil
}

// ContainerInfo checks container status and lists registered UEs via --dump.
func (c *DockerClient) ContainerInfo(ctx context.Context) (*ContainerInfo, error) {
	// Check container is running
	tCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tCtx, "docker", "inspect", "--format", "{{.State.Running}} {{.State.StartedAt}}", c.container)
	out, err := cmd.Output()
	if err != nil {
		return &ContainerInfo{Running: false}, nil
	}
	parts := strings.Fields(strings.TrimSpace(string(out)))
	running := len(parts) > 0 && parts[0] == "true"
	info := &ContainerInfo{Running: running}
	if !running {
		return info, nil
	}
	if len(parts) >= 2 {
		if t, err := time.Parse(time.RFC3339Nano, parts[1]); err == nil {
			info.UptimeSeconds = int(time.Since(t).Seconds())
		}
	}

	// List UEs via nr-cli --dump
	dump, err := c.exec(ctx, "nr-cli", "--dump")
	if err == nil {
		for _, line := range strings.Split(dump, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "imsi-") {
				info.RegisteredSUPIs = append(info.RegisteredSUPIs, line)
			}
		}
	}
	return info, nil
}

// ---- output parsers --------------------------------------------------------

func parseStatus(supi, out string) *UEStatus {
	s := &UEStatus{SUPI: supi}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MM-State:") || strings.HasPrefix(line, "mm-state:") {
			s.MMState = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(line, "CM-State:") || strings.HasPrefix(line, "cm-state:") {
			s.CMState = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	// Also look for "MM-REGISTERED" anywhere in the output
	if strings.Contains(out, "MM-REGISTERED") {
		s.MMState = "MM-REGISTERED"
		s.Registered = true
	} else if strings.Contains(out, "REGISTERED") {
		s.Registered = true
	}
	return s
}

func parsePDUSession(out string) *PDUSession {
	s := &PDUSession{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Session Id:") || strings.HasPrefix(line, "session-id:") {
			if id, err := strconv.Atoi(strings.TrimSpace(strings.SplitN(line, ":", 2)[1])); err == nil {
				s.SessionID = id
			}
		} else if strings.HasPrefix(line, "Address:") || strings.HasPrefix(line, "UE Address:") {
			s.UEAddr = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return s
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if ok := false; !ok {
		return -1
	}
	_ = exitErr
	return -1
}

// ---- MockClient (for unit tests) -------------------------------------------

// MockClient returns configurable canned responses without touching Docker.
type MockClient struct {
	StatusFn    func(ctx context.Context, supi string) (*UEStatus, error)
	EstablishFn func(ctx context.Context, supi, dnn string) (*PDUSession, error)
	ReleaseFn   func(ctx context.Context, supi string, sessionID int) error
	DeregFn     func(ctx context.Context, supi string) error
	ContainerFn func(ctx context.Context) (*ContainerInfo, error)
}

func (m *MockClient) UEStatus(ctx context.Context, supi string) (*UEStatus, error) {
	if m.StatusFn != nil {
		return m.StatusFn(ctx, supi)
	}
	return &UEStatus{SUPI: supi, MMState: "MM-REGISTERED", Registered: true}, nil
}

func (m *MockClient) PDUSessionEstablish(ctx context.Context, supi, dnn string) (*PDUSession, error) {
	if m.EstablishFn != nil {
		return m.EstablishFn(ctx, supi, dnn)
	}
	return &PDUSession{SessionID: 1, UEAddr: "10.0.0.1", DNNName: dnn}, nil
}

func (m *MockClient) PDUSessionRelease(ctx context.Context, supi string, id int) error {
	if m.ReleaseFn != nil {
		return m.ReleaseFn(ctx, supi, id)
	}
	return nil
}

func (m *MockClient) Deregister(ctx context.Context, supi string) error {
	if m.DeregFn != nil {
		return m.DeregFn(ctx, supi)
	}
	return nil
}

func (m *MockClient) ContainerInfo(ctx context.Context) (*ContainerInfo, error) {
	if m.ContainerFn != nil {
		return m.ContainerFn(ctx)
	}
	return &ContainerInfo{Running: true, RegisteredSUPIs: []string{"imsi-001010000000001"}, ActiveSessions: 0}, nil
}
