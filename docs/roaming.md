<!-- tier: public -->
# Roaming — using it and connecting another core

This guide explains what roaming means in ClaudIA 5GC, how to try it with the built-in test home
network, and the main steps to connect **another core** (a second ClaudIA 5GC or any other 5GC)
as a roaming partner. The exact interop profile (certificates, API versions, purposes) is in
[`n32-interop-profile.md`](n32-interop-profile.md); procedure designs are in the
[members documentation](https://www.claudia5gc.dev/docs/members/).

## 1. What roaming means in this core

| Item | Status |
|---|---|
| Edge proxy | Each core has a **SEPP**. The local core's SEPP is the `sepp` container (N32 port **8443**, SBI **8014**, metrics **9115**) |
| N32 security mode | **TLS only** (mutual TLS, per-PLMN trust anchors). **PRINS is not supported**: a partner that offers only PRINS gets `403 NEGOTIATION_NOT_ALLOWED` and cannot interwork |
| Roaming registration | **Done.** A UE of a foreign home PLMN registers on this core: the visited AMF routes Nausf (5G AKA) and Nudm (UECM, SDM) to the home AUSF/UDM through `sepp` and the partner SEPP (`3gpp-Sbi-Target-apiRoot`). Live-validated with the test home network |
| Home-routed PDU session | **Done.** A roaming UE's data session is anchored in the home network: the visited SMF (V-SMF) talks to the home SMF (H-SMF) over N16 through `sepp` and the partner SEPP, and user traffic flows V-UPF -> N9 -> H-UPF to the home data network. The UE gets its IP from the home SMF pool. Live-validated with the test home network (`make roaming-e2e`). The partner needs `home_nfs.smf_api_root` (section 4); without it the PDU session of a roaming UE is rejected (5GMM #90) |
| Other limits | NRF inter-PLMN discovery is not used (the AMF takes the partner AUSF/UDM apiRoots from configuration; this is a follow-up); S-NSSAIs must be the same in both PLMNs; 5G AKA only; no Steering of Roaming; partners are read at startup only (restart needed) |
| Release profiles | Legacy (`rel17`) peers get byte-identical messages. Caveat: under the `rel17` profile the UDM registers only `nudm-ueau` in its NRF, so a home SEPP cannot find the UDM's `nudm-uecm` / `nudm-sdm` by service name. A **home UDM that must serve roaming UEs through NRF discovery should run the `rel19` profile** (the default) |

## 2. Deployments

### Default core: ready, no partners

`make up` already starts `sepp` with a valid N32 certificate and **no partner**. It starts clean
(no WARN/ERROR), the N32 listener is ready, and roaming UEs are not accepted until you add a
partner (section 4). UEs of the local PLMN never use the roaming path.

### Test home network (opt-in `roaming` compose profile)

A **test fixture**, not a production setup: a fake home PLMN **001/02** next to the local core
**001/01**, made of `hsepp`, `hnrf`, `hausf`, `hudm` and `hudr` (plus its database). Use it to see
roaming working before connecting a real partner.

```bash
make pki                                         # N32 PKI incl. the test peer (idempotent)
make up RAN=ueransim                             # local core + gNB + UE
docker compose --profile core --profile roaming up -d   # add the test home network
make roaming-e2e                                 # roaming registration check (3 checks)
make sepp-e2e PROFILE=rel17                      # N32-c + N32-f NF discovery check (also PROFILE=rel19)
```

`make roaming-e2e` verifies (1) the home NRF holds AUSF/UDM/UDR profiles with home FQDNs,
(2) the roaming UE `imsi-001020000000001` (config `config/ueransim/ue-roaming.yaml`, UERANSIM
patch 0110) registers on the 001/01 core, (3) `fivegc_sepp_n32f_messages_total` increased.

The test partner is described by `config/roaming/partners-testpeer.yaml`. `make sepp-e2e` selects
it with `ROAMING_PARTNERS_FILE=/etc/5gc/roaming/partners-testpeer.yaml`. To use it by hand:

```bash
ROAMING_PARTNERS_FILE=/etc/5gc/roaming/partners-testpeer.yaml docker compose --profile core --profile roaming up -d --force-recreate sepp amf
```

## 3. Using roaming from the Portal

The portal **Roaming (N32)** page (see [`portal.md`](portal.md)) shows the local core and each
partner PLMN with a link state:

| State | Meaning |
|---|---|
| `UP` | both SEPPs hold an established N32 context for each other |
| `DEGRADED` | only one of the two SEPPs holds an established N32 context for the other |
| `DOWN` | partner configured but no N32 context |
| `NOT_DEPLOYED` | the partner side is not running (for example the test home network is stopped) |

Actions: **handshake** (start N32-c towards a partner) and **teardown** (end the context), start /
stop of the test home network, recent roaming warnings, and the live **Logs** page for `sepp`,
`hsepp` and the home NFs. The **partners editor** reads and writes the partners file
(`ROAMING_PARTNERS_FILE`) and restarts `sepp` and `amf` for you.

After the compose services were renamed (`vsepp` is now `sepp`) rebuild the portal image so it
uses the new names: `make portal-build` (or `make 5gcsa` to rebuild and start).

## 4. Connect another core (partner PLMN)

Both sides do the same steps; the partner list on each side names the other. Example: the partner
is PLMN **MCC 001 / MNC 02**.

### Step 1 — Agree identities and reachability

- Exchange PLMN IDs (MCC/MNC) and decide the release profile each side runs.
- SEPP FQDN convention: `sepp.5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org` (MNC zero-padded to 3
  digits), for example `sepp.5gc.mnc002.mcc001.3gppnetwork.org`. A partner may use another
  `sepp.` label (set `n32.sepp_fqdn`).
- The partner SEPP must be reachable on **TCP 8443** from your `sepp` container, and its FQDN must
  resolve (DNS, or an extra host / network alias in the compose file). Open the same port towards
  your core on the partner side. The local core publishes `8443:8443`.

### Step 2 — Exchange N32 CA certificates

Roaming trust is **one trust anchor per partner PLMN**. The SBI CA (`pki/ca.crt`) is never an N32
anchor and must not be sent to a partner.

```bash
make pki      # generates pki/n32/local/{ca,sepp}.{crt,key} for your PLMN (from config/operator.yaml)
openssl x509 -in pki/n32/local/sepp.crt -noout -ext subjectAltName
```

- **You send** `pki/n32/local/ca.crt` (your N32 CA bundle). Never send private keys.
- **You receive** the partner N32 CA bundle and place it at
  `pki/n32/peers/<MCC>-<MNC>/ca.crt`, for example `pki/n32/peers/001-02/ca.crt`.
- Your own N32 certificate (`pki/n32/local/sepp.crt`) carries SAN `sepp.5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org`
  and `*.` of the same name (for telescopic FQDNs), EKU serverAuth + clientAuth. If you bring your
  own certificate from an operator CA, it needs the same SANs: the PLMN of the peer is read from
  the SAN names ending in `mnc<3 digits>.mcc<3 digits>.3gppnetwork.org`, and a certificate
  without one is rejected.

### Step 3 — Write the partners file and restart

Start from `config/roaming/partners.example.yaml` and save it in the same directory as `partners.yaml` (operator-specific, created by you, not in the repository)
(or edit it in the Portal partners editor, which restarts for you). Schema per partner:

```yaml
partners:
  - plmn: {mcc: "001", mnc: "02"}
    n32:
      ca_file: /etc/5gc/pki/n32/peers/001-02/ca.crt      # required: partner trust anchor
      sepp_fqdn: sepp.5gc.mnc002.mcc001.3gppnetwork.org  # optional, derived from the PLMN
      address: sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443   # optional: present = we initiate N32-c at startup
    home_nfs:                                            # for roaming registration
      ausf_api_root: https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002
      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003
      smf_api_root: https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004   # for home-routed PDU sessions (https, no path)
```

```bash
docker compose restart sepp amf        # the file is read at startup only
```

A missing file means "no partners"; a present but invalid file stops `sepp` at startup (fail
closed). `home_nfs` is optional for SEPP-only interconnect.

### Step 4 — AMF side (roaming registration)

The AMF reads the same partners file. Every partner with `home_nfs` becomes a **home PLMN** the
AMF accepts and routes to. The AMF `roaming:` block in `nf/amf/config/dev.yaml` is
`enabled: true`, `sepp_address: sepp:8014` and an optional inline `home_plmns` list (same fields
as `home_nfs`; the file wins). A UE whose home PLMN is not listed is rejected with 5GMM #11.

For the partner to serve your roamers:

- The partner must reach AUSF/UDM from its SEPP. In a non-ClaudIA core, the AUSF and UDM must be
  registered in the partner NRF with their FQDNs, and the UDM with services `nudm-ueau`,
  `nudm-uecm` and `nudm-sdm` (a home SEPP resolves them by service name).
- The partner AUSF must authorise your serving network (`5G:mnc<MNC3>.mcc<MCC>.3gppnetwork.org`
  of your PLMN); on a ClaudIA home AUSF this is `roaming.authorized_serving_networks`.
- Each side signals the apiRoots in `home_nfs`; ask the partner for its AUSF and UDM apiRoots.

### Step 5 — UE / SIM side

The subscriber is provisioned in the **partner** home network (home PLMN = partner PLMN). The UE
must be allowed to select a visited PLMN. With UERANSIM use the VPLMN selection patch 0110
(`allowRoaming: true`, example `config/ueransim/ue-roaming.yaml`). A real UE/SIM needs your PLMN
allowed by its roaming agreement (preferred PLMN lists).

### Step 6 — Verify

```bash
curl -s http://localhost:9115/admin/v1/n32/partners | jq   # partner listed, source "file"
curl -s http://localhost:9115/admin/v1/n32/contexts | jq   # N32 context for the partner
curl -s http://localhost:9115/metrics | grep -E 'fivegc_sepp_n32c_context_established|fivegc_sepp_n32c_handshake_total|fivegc_sepp_n32f_messages_total|fivegc_sepp_n32_tls_reject_total'
docker logs sepp 2>&1 | grep -E 'exchange-capability|n32 initiator exchange completed|n32-f message forwarded'
docker logs amf 2>&1 | grep -i roaming
```

Expected: the portal link is **UP**; `fivegc_sepp_n32c_context_established{peer_plmn="001-02"} 1`;
`fivegc_sepp_n32_tls_reject_total` does not grow; after a roamer registers,
`fivegc_sepp_n32f_messages_total` increases and the AMF logs `RoamingRegistration` lines.

**Decrypted capture** (to see the N32 HTTP/2 messages):

```bash
SEPP_KEYLOG_DIR=1 docker compose --profile core up -d --force-recreate sepp   # TLS keys to pcaps/sepp-keys/sepp.keys
docker exec -d sepp-pcap sh -c "tcpdump -i any -U -s 0 -w /pcaps/n32.pcap 'tcp port 8443 or tcp port 8014'"   # capture on the sepp-pcap sidecar
# reproduce the handshake or registration, then stop the capture and decrypt:
docker exec sepp-pcap sh -c 'pkill -INT tcpdump'
tshark -r pcaps/sepp/n32.pcap -o tls.keylog_file:pcaps/sepp-keys/sepp.keys -Y http2
```

`make sepp-e2e` does this automatically when run as `SEPP_KEYLOG_DIR=1 make sepp-e2e` and writes
`pcaps/sepp/sepp-e2e-<profile>.pcap` plus `pcaps/sepp-keys/all-<profile>.keys`. The key log
contains secrets of live sessions: keep it local.

### Step 7 — Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| N32-c `403` (sender_domain_mismatch in the `sepp` log) | the `sender` FQDN does not end in `.5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org` of the certificate PLMN. Fix the partner SEPP FQDN or its certificate SAN |
| N32-c `403` (target_plmn_not_served) | the partner addressed another PLMN than yours as `targetPlmnId`. Check both PLMN IDs |
| N32-c `403` (plmn_mismatch) | `plmnIdList` or the sender PLMN is not the PLMN of the certificate |
| N32-c `403 NEGOTIATION_NOT_ALLOWED` | the partner offers PRINS only. Not supported (TLS mode only) |
| `fivegc_sepp_n32_tls_reject_total{reason}` grows | `no_plmn`: certificate has no `mnc..mcc..3gppnetwork.org` SAN. `not_partner`: PLMN not in your partners file. `anchor_conflict`: SANs map to different anchors. `chain`: certificate not signed by the anchor you placed in `peers/<MCC>-<MNC>/ca.crt` (often the SBI CA or the wrong CA was sent). `plmn_mismatch`: N32-c sender PLMN differs from the certificate PLMN |
| Handshake never starts | no `n32.address` in the partner entry on your side, FQDN does not resolve, or port 8443 blocked; the initiator retries with backoff for a limited number of attempts, so restart `sepp` after fixing |
| `504 TARGET_NF_NOT_REACHABLE` on N32-f | the home NRF has no matching NF (AUSF/UDM, with `nudm-uecm`/`nudm-sdm` for the UDM) registered for the target. Register it with its FQDN, or run the home UDM on the `rel19` profile |
| UE rejected, 5GMM #11 (PLMN not allowed) | the UE home PLMN is not in the AMF home PLMNs (no `home_nfs` for that partner, or AMF not restarted) |
| UE rejected, 5GMM #73 | the home AUSF refused the serving network (`SERVING_NETWORK_NOT_AUTHORIZED`); authorise your serving network at the home AUSF |
| UE rejected, 5GMM #22 | the Nausf/Nudm path failed through the SEPP (timeout, 504, SEPP down) or the SUPI is not under the claimed home PLMN. Check `sepp` and `amf` logs with `procedure=N32Handshake` / `RoamingRegistration` |

## 5. Interoperability caveats

- **PRINS-only peers cannot interwork** (TLS mode only; no application-layer security, no
  Roaming Intermediaries).
- SNPN peers are not supported.
- Home-routed PDU sessions work; the S-NSSAI values must be the same in both PLMNs (no mapping). A UE-initiated release of a home-routed session is sent to the home SMF as an Update with `UE_REQ_PDU_SES_REL`; the visited SMF builds the release command itself instead of waiting for the home SMF's update, so interworking with another vendor's home SMF may need adjustment.
- A partner partners-file change needs a restart of `sepp` and `amf`.
- Passing the test home network is not proof of interworking with another vendor: verify the
  profile in [`n32-interop-profile.md`](n32-interop-profile.md) against the partner's.
