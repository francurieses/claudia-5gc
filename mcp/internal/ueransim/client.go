// Package ueransim drives UERANSIM UE containers through mgmt-portal's
// nr-cli proxy (POST /api/v1/ueransim/nr-cli). MCP never talks to Docker
// directly: it is reachable over SSE by external LLM clients, so mounting
// the Docker socket into it would hand out root-equivalent host access to
// whoever can drive a tool call. mgmt-portal already holds that socket
// (read-only mount, internal network only) and exposes exec as a narrow,
// validated HTTP endpoint — this client is a thin wrapper around it.
package ueransim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// UEStatus captures nr-cli STATUS output for one UE.
type UEStatus struct {
	SUPI       string
	MMState    string // e.g. MM-REGISTERED, MM-DEREGISTERED
	CMState    string // e.g. CM-CONNECTED, CM-IDLE
	Registered bool
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

// PortalClient calls nr-cli via mgmt-portal's HTTP proxy, targeting a fixed
// UERANSIM UE container by name.
type PortalClient struct {
	baseURL   string
	container string
	http      *http.Client
	log       *slog.Logger
}

// NewPortalClient returns a client targeting the named container through
// mgmt-portal at baseURL (e.g. http://mgmt-portal:8080).
func NewPortalClient(baseURL, container string, timeout time.Duration, log *slog.Logger) *PortalClient {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if container == "" {
		container = "ueransim-ue"
	}
	return &PortalClient{
		baseURL:   strings.TrimRight(baseURL, "/"),
		container: container,
		http:      &http.Client{Timeout: timeout},
		log:       log,
	}
}

// nrCLIResult mirrors mgmt-portal's docker.ExecResult JSON shape.
type nrCLIResult struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

func (c *PortalClient) nrCLI(ctx context.Context, supi, command string) (string, error) {
	start := time.Now()
	reqBody, _ := json.Marshal(map[string]string{
		"container": c.container,
		"supi":      supi,
		"command":   command,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/ueransim/nr-cli", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("build nr-cli request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		c.log.InfoContext(ctx, "ueransim nr-cli",
			"container", c.container, "command", command,
			"duration_ms", time.Since(start).Milliseconds(), "error", err.Error())
		return "", fmt.Errorf("mgmt-portal nr-cli: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		c.log.InfoContext(ctx, "ueransim nr-cli",
			"container", c.container, "command", command,
			"duration_ms", time.Since(start).Milliseconds(), "status", resp.StatusCode)
		return "", fmt.Errorf("mgmt-portal nr-cli: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var result nrCLIResult
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("mgmt-portal nr-cli: decode response: %w", err)
	}
	c.log.InfoContext(ctx, "ueransim nr-cli",
		"container", c.container, "command", command,
		"duration_ms", time.Since(start).Milliseconds(), "exit_code", result.ExitCode)
	if result.ExitCode != 0 {
		return "", fmt.Errorf("nr-cli %s: exit %d: %s", command, result.ExitCode, strings.TrimSpace(result.Output))
	}
	return strings.TrimSpace(result.Output), nil
}

// UEStatus returns the current GMM/CM state for a SUPI.
func (c *PortalClient) UEStatus(ctx context.Context, supi string) (*UEStatus, error) {
	out, err := c.nrCLI(ctx, supi, "STATUS")
	if err != nil {
		return nil, fmt.Errorf("ueransim: STATUS %s: %w", supi, err)
	}
	return parseStatus(supi, out), nil
}

// PDUSessionEstablish triggers a PDU session for the UE.
func (c *PortalClient) PDUSessionEstablish(ctx context.Context, supi, dnn string) (*PDUSession, error) {
	cmd := fmt.Sprintf("ps-establish default %s", dnn)
	out, err := c.nrCLI(ctx, supi, cmd)
	if err != nil {
		return nil, fmt.Errorf("ueransim: ps-establish %s %s: %w", supi, dnn, err)
	}
	return parsePDUSession(out), nil
}

// PDUSessionRelease releases a specific PDU session.
func (c *PortalClient) PDUSessionRelease(ctx context.Context, supi string, sessionID int) error {
	cmd := fmt.Sprintf("ps-release %d", sessionID)
	if _, err := c.nrCLI(ctx, supi, cmd); err != nil {
		return fmt.Errorf("ueransim: ps-release %s %d: %w", supi, sessionID, err)
	}
	return nil
}

// Deregister triggers UE-initiated deregistration.
func (c *PortalClient) Deregister(ctx context.Context, supi string) error {
	if _, err := c.nrCLI(ctx, supi, "deregister normal"); err != nil {
		return fmt.Errorf("ueransim: deregister %s: %w", supi, err)
	}
	return nil
}

// statusResponse mirrors the subset of mgmt-portal's
// GET /api/v1/ueransim/status this client needs. Kept minimal and local
// rather than importing tools/mgmt-portal, a separate chi-based module.
type statusResponse struct {
	Containers []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	} `json:"containers"`
	UEs []struct {
		SUPI      string `json:"supi"`
		Container string `json:"container"`
		Sessions  []any  `json:"sessions"`
	} `json:"ues"`
}

// ContainerInfo checks container status and lists registered UEs via
// mgmt-portal's combined status endpoint (container list + AMF-context-backed
// UE list), which is more reliable than parsing `nr-cli --dump` text.
func (c *PortalClient) ContainerInfo(ctx context.Context) (*ContainerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/ueransim/status", nil)
	if err != nil {
		return nil, fmt.Errorf("build status request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &ContainerInfo{Running: false}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &ContainerInfo{Running: false}, nil
	}

	var sr statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode ueransim status: %w", err)
	}

	info := &ContainerInfo{}
	for _, ctr := range sr.Containers {
		if ctr.Name == c.container {
			info.Running = ctr.State == "running"
			break
		}
	}
	for _, ue := range sr.UEs {
		if ue.Container == c.container {
			info.RegisteredSUPIs = append(info.RegisteredSUPIs, ue.SUPI)
			info.ActiveSessions += len(ue.Sessions)
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
