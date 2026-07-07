package api

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	dockerclient "github.com/francurieses/claudia-5gc/tools/mgmt-portal/internal/docker"
)

// pcapSidecars maps NF name → sidecar container name.
// "core" is special: network_mode:host so it sees ALL Docker bridge interfaces
// and captures every inter-NF packet with a 172.30.0.0/16 BPF filter.
var pcapSidecars = map[string]string{
	"core": "core-pcap",
	// Control-plane
	"nrf":  "nrf-pcap",
	"amf":  "amf-pcap",
	"ausf": "ausf-pcap",
	"udm":  "udm-pcap",
	"udr":  "udr-pcap",
	"smf":  "smf-pcap",
	"pcf":  "pcf-pcap",
	"upf":  "upf-pcap",
	"nssf": "nssf-pcap",
	"smsf": "smsf-pcap",
	"bsf":  "bsf-pcap",
	"nef":  "nef-pcap",
	"lmf":  "lmf-pcap",
}

// PCAPStatus describes the state of a PCAP sidecar.
type PCAPStatus struct {
	NF        string `json:"nf"`
	Container string `json:"container"`
	Capturing bool   `json:"capturing"` // tcpdump actively writing packets
	Paused    bool   `json:"paused"`    // tcpdump suspended (SIGSTOP)
	Files     int    `json:"files"`
}

// PCAPFile describes a single capture file.
type PCAPFile struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size_bytes"`
	ModTime time.Time `json:"mod_time"`
}

func (d Deps) handlePCAPStatus(w http.ResponseWriter, r *http.Request) {
	statuses := make([]PCAPStatus, 0, len(pcapSidecars))
	for nf, ctr := range pcapSidecars {
		st := PCAPStatus{NF: nf, Container: ctr}
		if d.Docker != nil {
			svcs, _ := d.Docker.List(r.Context())
			for _, svc := range svcs {
				if svc.Name == ctr && svc.State == "running" {
					state := queryTcpdumpState(r.Context(), d.Docker, ctr)
					st.Capturing = state == "capturing"
					st.Paused = state == "paused"
					break
				}
			}
		}
		files, _ := listPCAPFiles(nf)
		st.Files = len(files)
		statuses = append(statuses, st)
	}
	writeJSON(w, http.StatusOK, statuses)
}

// queryTcpdumpState checks whether tcpdump is running inside the container.
// Returns "stopped", "capturing", or "paused".
// Treats zombie processes (state Z) as stopped — they occur when PID 1 doesn't
// reap children; init:true in docker-compose eliminates them, but we stay defensive.
func queryTcpdumpState(ctx context.Context, docker *dockerclient.Client, ctr string) string {
	res, err := docker.Exec(ctx, ctr, []string{"sh", "-c",
		`pid=$(pgrep -o tcpdump 2>/dev/null); ` +
			`if [ -z "$pid" ]; then echo stopped; ` +
			`else state=$(awk '/^State:/{print $2}' /proc/$pid/status 2>/dev/null); ` +
			`case "$state" in T) echo paused;; Z|"") echo stopped;; *) echo capturing;; esac; fi`,
	})
	if err != nil || res.ExitCode != 0 {
		return "stopped"
	}
	return strings.TrimSpace(res.Output)
}

func (d Deps) handlePCAPStart(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	ctr, ok := pcapSidecars[nf]
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown nf: %s", nf))
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker not available")
		return
	}
	// Idempotent: only start tcpdump if not already running or paused.
	// Explicitly excludes zombies (state Z) so that a previously stopped capture
	// does not block a new one from starting.
	//
	// core-pcap runs with network_mode:host so it sees all Docker bridge
	// interfaces. We add a BPF filter to limit capture to the 5GC subnets
	// (172.30.0.0/16 covers sbi/n2/n4/n3/n6). Per-NF sidecars run inside the
	// NF's network namespace and need no filter — they only see that NF's traffic.
	bpfFilter := ""
	if nf == "core" {
		bpfFilter = `'net 172.30.0.0/16' `
	}
	cmd := fmt.Sprintf(
		`pid=$(pgrep -o tcpdump 2>/dev/null); `+
			`state=; [ -n "$pid" ] && state=$(awk '/^State:/{print $2}' /proc/$pid/status 2>/dev/null); `+
			`if [ -z "$pid" ] || [ "$state" = "Z" ] || [ -z "$state" ]; then `+
			`tcpdump -i any -n -w '/pcaps/%s-%%Y%%m%%d-%%H%%M%%S.pcap' -G 300 -W 12 %s`+
			`</dev/null >/dev/null 2>&1 & echo $! > /tmp/tcpdump.pid; fi`,
		nf, bpfFilter,
	)
	res, err := d.Docker.Exec(r.Context(), ctr, []string{"sh", "-c", cmd})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.ExitCode != 0 {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("tcpdump start failed (exit %d): %s", res.ExitCode, res.Output))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "started", "container": ctr})
}

func (d Deps) handlePCAPStop(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	ctr, ok := pcapSidecars[nf]
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown nf: %s", nf))
		return
	}
	if d.Docker == nil {
		writeError(w, http.StatusServiceUnavailable, "docker not available")
		return
	}
	// Resume if paused so SIGTERM is delivered, then terminate gracefully.
	res, err := d.Docker.Exec(r.Context(), ctr, []string{"sh", "-c",
		`pid=$(cat /tmp/tcpdump.pid 2>/dev/null); ` +
			`[ -n "$pid" ] && kill -CONT "$pid" 2>/dev/null; ` +
			`[ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null; ` +
			`rm -f /tmp/tcpdump.pid`,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.ExitCode != 0 {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("stop failed: %s", res.Output))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "container": ctr})
}

func (d Deps) handlePCAPPause(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	if err := execPCAPSignal(d, r, nf, "STOP"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (d Deps) handlePCAPResume(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	if err := execPCAPSignal(d, r, nf, "CONT"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "resumed"})
}

func (d Deps) handlePCAPRotate(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	if err := execPCAPSignal(d, r, nf, "HUP"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rotated"})
}

// execPCAPSignal sends signal to the tcpdump process inside the PCAP sidecar.
// signal should be a bare name accepted by kill(1): STOP, CONT, HUP, TERM, etc.
func execPCAPSignal(d Deps, r *http.Request, nf, signal string) error {
	ctr, ok := pcapSidecars[nf]
	if !ok {
		return fmt.Errorf("unknown pcap nf: %s", nf)
	}
	if d.Docker == nil {
		return fmt.Errorf("docker not available")
	}
	cmd := fmt.Sprintf("kill -%s $(cat /tmp/tcpdump.pid 2>/dev/null) 2>/dev/null", signal)
	res, err := d.Docker.Exec(r.Context(), ctr, []string{"sh", "-c", cmd})
	if err != nil {
		return fmt.Errorf("exec signal %s: %w", signal, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("signal %s failed (exit %d): %s", signal, res.ExitCode, res.Output)
	}
	return nil
}

func (d Deps) handlePCAPFiles(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	files, err := listPCAPFiles(nf)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, files)
}

// handlePCAPDownload serves a single PCAP file as a download.
func (d Deps) handlePCAPDownload(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	filename := chi.URLParam(r, "filename")

	if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}
	if _, ok := pcapSidecars[nf]; !ok {
		writeError(w, http.StatusBadRequest, "unknown nf")
		return
	}

	path := filepath.Join("/pcaps", nf, filename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

// handlePCAPDeleteFile deletes a single PCAP file.
func (d Deps) handlePCAPDeleteFile(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	filename := chi.URLParam(r, "filename")

	if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}
	if _, ok := pcapSidecars[nf]; !ok {
		writeError(w, http.StatusBadRequest, "unknown nf")
		return
	}

	path := filepath.Join("/pcaps", nf, filename)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "file not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": filename})
}

type bulkFilesRequest struct {
	Files []string `json:"files"`
}

// handlePCAPBulkDelete deletes multiple PCAP files.
func (d Deps) handlePCAPBulkDelete(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	if _, ok := pcapSidecars[nf]; !ok {
		writeError(w, http.StatusBadRequest, "unknown nf")
		return
	}

	var req bulkFilesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	deleted := 0
	for _, filename := range req.Files {
		if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
			continue
		}
		if err := os.Remove(filepath.Join("/pcaps", nf, filename)); err == nil {
			deleted++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

// handlePCAPBulkDownload creates a ZIP archive of the requested files and streams it.
func (d Deps) handlePCAPBulkDownload(w http.ResponseWriter, r *http.Request) {
	nf := chi.URLParam(r, "nf")
	if _, ok := pcapSidecars[nf]; !ok {
		writeError(w, http.StatusBadRequest, "unknown nf")
		return
	}

	var req bulkFilesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-pcaps.zip"`, nf))

	zw := zip.NewWriter(w)
	defer zw.Close()

	for _, filename := range req.Files {
		if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
			continue
		}
		f, err := os.Open(filepath.Join("/pcaps", nf, filename))
		if err != nil {
			continue
		}
		fw, err := zw.Create(filename)
		if err != nil {
			f.Close()
			continue
		}
		io.Copy(fw, f) //nolint:errcheck
		f.Close()
	}
}

func listPCAPFiles(nf string) ([]PCAPFile, error) {
	dir := filepath.Join("/pcaps", nf)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []PCAPFile{}, nil
		}
		return nil, err
	}

	files := make([]PCAPFile, 0, len(entries))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pcap") && !strings.HasSuffix(e.Name(), ".pcapng") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, PCAPFile{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}
	return files, nil
}
