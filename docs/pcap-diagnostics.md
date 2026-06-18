# PCAP Diagnostics — 5GC Rel-17

Analysis and solutions for traffic capture on N2 (NGAP), SBI (HTTP/2), and other interfaces.

---

## 🔴 Problem 1: I don't see NGAP messages

### What should I see?

- NGAP messages over SCTP on port **38412**
- Examples: `InitialUEMessage`, `UplinkNASTransport`, `DownlinkNASTransport`, etc.
- N2 interface between gNB (UERANSIM) and AMF

### Diagnosis

#### 1.1 Is UERANSIM running?

```bash
docker ps | grep -i ueransim
# You should see: ueransim-gnb, ueransim-ue (or similar)
```

If they are **NOT** running:
```bash
make ueransim      # Start core + UERANSIM + gNB + UE
```

#### 1.2 Is N2 network connected?

```bash
docker network inspect 5gc-n2
# Verify that 'amf' is in the list of connected containers
```

If N2 is misconfigured:
```bash
docker network ls | grep n2
# Should exist: 5gc-n2

docker network disconnect 5gc-n2 amf 2>/dev/null || true
docker network connect 5gc-n2 amf
docker network connect 5gc-n2 ueransim-gnb  # or your container name
```

#### 1.3 Is port 38412 open on AMF?

```bash
docker ps | grep amf
# Look for: 0.0.0.0:38412->38412/tcp

docker logs amf | tail -20
# Look for lines about "SCTP listen" or "N2"
```

#### 1.4 Are PCAPs captured on the correct network?

```bash
# See what interfaces the amf-pcap container sees
docker exec amf-pcap ip link show

# See what IP addresses it has
docker exec amf-pcap ip addr show

# Verify it's on 5gc-n2
docker exec amf-pcap ip route
```

### Solution

**If UERANSIM is not running:**

```bash
make ueransim
# Wait for all containers to start (1-2 min)

# Verify gNB + UE are connected
docker logs ueransim-gnb | grep -i "listen\|sctp\|connected"
docker logs ueransim-ue  | grep -i "register\|registration"
```

**If N2 network is disconnected:**

```bash
# Reconnect both sides
docker network disconnect 5gc-n2 amf
docker network connect 5gc-n2 amf

docker network disconnect 5gc-n2 ueransim-gnb
docker network connect 5gc-n2 ueransim-gnb
```

**If PCAP doesn't see N2:**

The `amf-pcap` container uses `network_mode: "service:amf"`, which means it **shares exactly the AMF's network namespace**. If AMF doesn't see N2, neither does the PCAP.

Alternative solution — capture at host level:

```bash
# On the host (if Docker networks are available)
sudo tcpdump -i docker0 -w /tmp/n2-capture.pcap port 38412
# Then analyze with Wireshark
```

---

## 🟠 Problem 2: I only see HTTP, not HTTP/2

### What should I see?

In Wireshark, you should see:

```
Frame X: TLS/SSL (encrypted)
  └─ Transport Layer Security (TLS 1.3)
     └─ Application Data [Encrypted with AES-GCM]
```

Or, if Wireshark decodes TLS:

```
Frame X: HTTP/2
  └─ Settings Frame
  └─ Headers Frame
     └─ GET /nrf/oauth2/token HTTP/2
```

### Why do you only see HTTP/1.1?

There are two cases:

#### Case A: You see `GET /metrics HTTP/1.1`

✅ **This is CORRECT**. These are **Prometheus metrics** (port 9101):
- Port: 9101 (unencrypted)
- Protocol: HTTP/1.1 (as-is)
- Source: Prometheus container
- Content: OpenMetrics

**This is NOT SBI traffic. SBI is on ports 8000-8005.**

#### Case B: You don't see ANYTHING that is HTTP/2

❌ **SBI traffic is encrypted.**

SBI uses:
- **Ports**: 8000 (NRF), 8001 (AMF), 8002 (AUSF), 8003 (UDM), 8005 (UDR)
- **Protocol**: HTTP/2 over TLS 1.3
- **Certificates**: PKI in `./pki/` (self-signed)

Wireshark **DOES SEE TCP/TLS packets**, but:
1. **It does not decode HTTP/2** without the private keys
2. **It shows them as "TLS" or "Encrypted Application Data"**

### Solution: View HTTP/2 in Wireshark

**Option 1: Import private keys into Wireshark**

1. In Wireshark: `Preferences` → `Protocols` → `TLS`
2. Click "Edit" on `RSA keys list`
3. Add:
   ```
   IP Address: 172.30.0.2 (or your NRF's IP)
   Port: 8000
   Protocol: http
   Key File: /home/franc/proyectos/5gc-rel17/pki/nrf.key
   ```
4. Repeat for amf (8001), ausf (8002), etc.
5. Restart Wireshark

**Option 2: Use SSL/TLS session logs (SSLKEYLOGFILE)**

Modify AMF to export keys:

```go
// In nf/amf/internal/server/server.go
os.Setenv("SSLKEYLOGFILE", "/tmp/sslkeys.log")
```

Then in Wireshark:
```
Preferences → Protocols → TLS → (Pre)-Master Secret Log Filename: /tmp/sslkeys.log
```

**Option 3: Capture pre-TLS traffic (if using localhost)**

If you run everything locally (without Docker):
```bash
./scripts/run-nf.sh amf
```
Then tcpdump will see the plaintext HTTP/2.

### Quick verification

```bash
# Check if there's TLS traffic on port 8000 (SBI)
strings ./pcaps/nrf/nrf-*.pcap | grep -E "^.{0,10}SBI|^.{0,10}TLS" | head -20

# Or directly: search for "StartTLS" or TLS handshake bytes
hexdump -C ./pcaps/nrf/nrf-*.pcap | grep -i "160303"  # TLS record type + version
```

---

## 🟢 Quick Solution: pcap-control.sh script

An interactive script has been added to control capture:

```bash
./scripts/pcap-control.sh                 # Interactive menu mode
./scripts/pcap-control.sh status          # View current status
./scripts/pcap-control.sh pause amf       # Pause AMF capture
./scripts/pcap-control.sh resume amf      # Resume
./scripts/pcap-control.sh rotate nrf      # Rotate PCAP file
./scripts/pcap-control.sh list amf        # List files
./scripts/pcap-control.sh stats ./pcaps/amf/amf-20260513-150805.pcap
```

---

## 📋 Checklist: "I want to see NGAP"

- [ ] `docker ps | grep ueransim` — UERANSIM running
- [ ] `docker network inspect 5gc-n2` — AMF + gNB on the network
- [ ] `docker logs ueransim-gnb` — Look for "listen" or "ready"
- [ ] `docker logs amf` — Look for "NGAP" or "N2"
- [ ] `./scripts/pcap-control.sh rotate amf` — New PCAP
- [ ] Wait 10s for traffic to appear
- [ ] Download the latest PCAP
- [ ] Open in Wireshark → `File` → `Open`

---

## 📋 Checklist: "I want to see HTTP/2"

- [ ] Confirm you see TLS traffic on ports 8000-8005
  ```bash
  strings ./pcaps/nrf/nrf-*.pcap | grep -E "GET|POST|HTTP"
  ```
- [ ] Import private keys into Wireshark (see Option 1 above)
- [ ] Or accept that you see "TLS" — that's what tcpdump captures (normal)

---

## 🔧 Additional troubleshooting

### "The script says amf-pcap is not running"

```bash
docker-compose -f docker-compose.yml \
  --profile core --profile observability \
  up -d amf-pcap
```

### "The tcpdump process doesn't respond to SIGSTOP"

The container might be in a zombie state. Restart it:

```bash
docker restart amf-pcap
```

### "I want to see only N2 traffic"

Modify docker-compose.yml:

```yaml
amf-pcap:
  command: >
    sh -c "tcpdump -i eth0 -w /pcaps/amf-%Y%m%d-%H%M%S.pcap \
    'sctp port 38412' -G 300 -W 12 -Z root"
```

Or for SBI:

```yaml
command: >
  sh -c "tcpdump -i eth0 -w /pcaps/amf-%Y%m%d-%H%M%S.pcap \
  'tcp port 8001 or tcp port 8000 or tcp port 8002' -G 300 -W 12 -Z root"
```

### "PCAP files are taking up too much space"

The `-G 300 -W 12` parameters mean:
- `-G 300`: rotate every 300s (5 min)
- `-W 12`: keep maximum 12 files (1 hour of rotation)

Adjust for less space:

```yaml
command: >
  sh -c "tcpdump -i any -w /pcaps/amf-%Y%m%d-%H%M%S.pcap -G 60 -W 4 -Z root"
  # Now: rotate every 60s, max 4 files (4 min of history)
```

---

## 📚 References

- NGAP spec: TS 38.413
- SBA HTTP/2 spec: TS 29.500 §4.4.1
- 3GPP OpenAPI: https://forge.3gpp.org/rep/all/5G_APIs (branch Rel-17)
