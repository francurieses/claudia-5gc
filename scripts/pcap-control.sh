#!/bin/bash
# pcap-control.sh — Interactive control of PCAP capture for NFs
# Handles pause, resume, listing, and basic analysis of PCAPs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAPS_DIR="$SCRIPT_DIR/pcaps"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Utilities
log_info() {
    echo -e "${BLUE}[ℹ]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*"
}

# Check if a PCAP container is running
check_container() {
    local nf=$1
    docker ps --format "table {{.Names}}" | grep -q "^${nf}-pcap$" && return 0 || return 1
}

# Get PID of tcpdump process inside the container
get_tcpdump_pid() {
    local nf=$1
    docker exec "${nf}-pcap" pgrep -f "tcpdump" 2>/dev/null || echo ""
}

# PAUSE capture (SIGSTOP)
pause_capture() {
    local nf=$1
    log_info "Pausing capture on $nf..."

    if ! check_container "$nf"; then
        log_error "Container ${nf}-pcap is not running"
        return 1
    fi

    local pid=$(get_tcpdump_pid "$nf")
    if [ -z "$pid" ]; then
        log_error "tcpdump process not found in ${nf}-pcap"
        return 1
    fi

    docker exec "${nf}-pcap" kill -SIGSTOP "$pid" 2>/dev/null || {
        log_error "Could not pause the process"
        return 1
    }

    log_success "Capture on $nf paused (PID: $pid)"
}

# RESUME capture (SIGCONT)
resume_capture() {
    local nf=$1
    log_info "Resuming capture on $nf..."

    if ! check_container "$nf"; then
        log_error "Container ${nf}-pcap is not running"
        return 1
    fi

    local pid=$(get_tcpdump_pid "$nf")
    if [ -z "$pid" ]; then
        log_error "tcpdump process not found in ${nf}-pcap"
        return 1
    fi

    docker exec "${nf}-pcap" kill -SIGCONT "$pid" 2>/dev/null || {
        log_error "Could not resume the process"
        return 1
    }

    log_success "Capture on $nf resumed (PID: $pid)"
}

# ROTATE files (SIGUSR1 — forces file rotation)
rotate_capture() {
    local nf=$1
    log_info "Rotating capture file for $nf..."

    if ! check_container "$nf"; then
        log_error "Container ${nf}-pcap is not running"
        return 1
    fi

    local pid=$(get_tcpdump_pid "$nf")
    if [ -z "$pid" ]; then
        log_error "tcpdump process not found in ${nf}-pcap"
        return 1
    fi

    docker exec "${nf}-pcap" kill -SIGUSR1 "$pid" 2>/dev/null || {
        log_error "Could not rotate the file"
        return 1
    }

    log_success "File rotated for $nf (wait 2s for write to complete)"
    sleep 2
}

# LIST PCAP files
list_pcaps() {
    local nf=$1
    local pcap_dir="$PCAPS_DIR/$nf"

    if [ ! -d "$pcap_dir" ]; then
        log_error "Directory $pcap_dir does not exist"
        return 1
    fi

    local count=$(ls -1 "$pcap_dir"/*.pcap 2>/dev/null | wc -l)
    if [ "$count" -eq 0 ]; then
        log_warn "No PCAP files for $nf"
        return 0
    fi

    echo ""
    log_info "PCAP files for $nf ($count files):"
    echo ""
    ls -lh "$pcap_dir"/*.pcap | awk '{print "  " $9, "(" $5 ")"}'
    echo ""
}

# DUMP basic statistics from a PCAP
pcap_stats() {
    local pcap_file=$1

    if [ ! -f "$pcap_file" ]; then
        log_error "File not found: $pcap_file"
        return 1
    fi

    # Extract basic statistics using hexdump + grep
    local size=$(stat -f%z "$pcap_file" 2>/dev/null || stat -c%s "$pcap_file" 2>/dev/null)
    local http_count=$(strings "$pcap_file" 2>/dev/null | grep -c "^HTTP/" || echo "0")
    local ngap_count=$(strings "$pcap_file" 2>/dev/null | grep -ic "ngap\|InitialUEMessage" || echo "0")

    echo ""
    log_info "Statistics for $(basename "$pcap_file"):"
    echo "  Size: $size bytes"
    echo "  HTTP messages detected: $http_count"
    echo "  NGAP mentions: $ngap_count"
    echo "  Last access: $(stat -c%y "$pcap_file" 2>/dev/null | cut -d' ' -f1-2)"
    echo ""
}

# STATUS of all sidecars
status() {
    echo ""
    log_info "Status of PCAP sidecars:"
    echo ""

    for nf in nrf amf; do
        if check_container "$nf"; then
            local pid=$(get_tcpdump_pid "$nf")
            if [ -z "$pid" ]; then
                echo "  ${nf}: ${RED}✗ Container running, tcpdump NOT FOUND${NC}"
            else
                # Try to detect state (works better on standard linux)
                # On Alpine/netshoot may not be available, assume active
                echo "  ${nf}: ${GREEN}● ACTIVE${NC} (PID: $pid)"
                echo "         Use 'pause $nf' to pause, 'resume $nf' to resume"
            fi
        else
            echo "  ${nf}: ${RED}✗ NOT RUNNING${NC}"
        fi
    done
    echo ""
}

# Interactive MENU
show_menu() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}  PCAP Control — 5GC Rel-17${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo ""
    echo "  NF:       [1] NRF    [2] AMF    [3] All"
    echo ""
    echo "  Actions:"
    echo "    [p] Pause       [r] Resume      [t] Rotate file"
    echo "    [l] List        [s] Stats       [e] Status"
    echo "    [h] Help        [q] Quit"
    echo ""
}

show_help() {
    cat << 'EOF'

PCAP Control — Complete Help
════════════════════════════════════════

COMMANDS:

  pause <nf>      Pause capture of an NF (SIGSTOP)
  resume <nf>     Resume capture (SIGCONT)
  rotate <nf>     Force PCAP file rotation
  list <nf>       List saved PCAP files
  stats <file>    Basic statistics of a PCAP
  status          Status of all sidecars

EXAMPLES:

  ./scripts/pcap-control.sh pause nrf
  ./scripts/pcap-control.sh resume amf
  ./scripts/pcap-control.sh rotate nrf
  ./scripts/pcap-control.sh list amf
  ./scripts/pcap-control.sh stats ./pcaps/amf/amf-20260513-150805.pcap
  ./scripts/pcap-control.sh status

NOTES:

  • PAUSE: Stops the tcpdump process but does NOT delete files
  • ROTATE: Closes current file and creates a new one (without losing data)
  • States:
    ● ACTIVE = capturing
    ⏸ PAUSED = not capturing (process T state)
    ✗ NOT RUNNING = container does not exist

COMMON ISSUES:

  ❌ I don't see NGAP messages
    → UERANSIM must be running: make ueransim
    → N2 must be connected: docker network inspect 5gc-n2

  ❌ I don't see HTTP/2 in Wireshark
    → It's TLS encrypted. Shows as "TLS" in Wireshark
    → Without private keys HTTP/2 is not decoded

  ❌ I only see HTTP/1.1
    → These are Prometheus metrics (port 9101)
    → SBI APIs are on HTTP/2 (port 8000+)

EOF
}

# Main
main() {
    case "${1:-}" in
        pause)
            pause_capture "${2:-amf}"
            ;;
        resume)
            resume_capture "${2:-amf}"
            ;;
        rotate)
            rotate_capture "${2:-amf}"
            ;;
        list)
            list_pcaps "${2:-amf}"
            ;;
        stats)
            pcap_stats "$2"
            ;;
        status)
            status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            # Interactive mode
            status
            while true; do
                show_menu
                read -p "Select option: " -r opt

                case "$opt" in
                    1) nf="nrf" ;;
                    2) nf="amf" ;;
                    3) nf="all" ;;
                    p|P)
                        if [ "$nf" = "all" ]; then
                            pause_capture nrf
                            pause_capture amf
                        else
                            pause_capture "${nf:-amf}"
                        fi
                        ;;
                    r|R)
                        if [ "$nf" = "all" ]; then
                            resume_capture nrf
                            resume_capture amf
                        else
                            resume_capture "${nf:-amf}"
                        fi
                        ;;
                    t|T)
                        if [ "$nf" = "all" ]; then
                            rotate_capture nrf
                            rotate_capture amf
                        else
                            rotate_capture "${nf:-amf}"
                        fi
                        ;;
                    l|L)
                        if [ "$nf" = "all" ]; then
                            list_pcaps nrf
                            list_pcaps amf
                        else
                            list_pcaps "${nf:-amf}"
                        fi
                        ;;
                    s|S)
                        read -p "PCAP path: " -r pcap_file
                        pcap_stats "$pcap_file"
                        ;;
                    e|E)
                        status
                        ;;
                    h|H)
                        show_help
                        ;;
                    q|Q)
                        log_info "Exiting..."
                        exit 0
                        ;;
                    *)
                        log_warn "Option not recognized"
                        ;;
                esac
            done
            ;;
    esac
}

main "$@"
