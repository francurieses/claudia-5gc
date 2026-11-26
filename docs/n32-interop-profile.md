<!-- tier: public -->
# N32 Interop Profile — connecting ClaudIA 5GC to a roaming partner

This page tells an operator what a roaming partner must provide to connect its core (another
vendor's core or a second ClaudIA 5GC) to the **local core** over N32, and gives a copy-paste
checklist. Procedure design and spec references are in the [members documentation](https://www.claudia5gc.dev/docs/members/). The local core's SEPP is the `sepp` container. For the full roaming guide (test home network, Portal, step-by-step onboarding, troubleshooting) see [`roaming.md`](roaming.md).

## 1. Profile summary

| Item | Local core offers / requires | Reference |
|---|---|---|
| Security mode | **TLS only** on N32-c and N32-f. **PRINS is not supported**: a partner that only offers PRINS gets `403 NEGOTIATION_NOT_ALLOWED` and cannot interwork (PRINS is out of scope) | TS 29.573 §5.2.2; TS 33.501 §13.1.2 |
| Transport | TLS 1.2 minimum, TLS 1.3 preferred, mutual authentication (both sides present a cert), HTTP/2 (ALPN `h2`) | TS 33.210 §6.2; TS 33.501 §13.1.2 |
| N32 port | **8443** (N32-c and N32-f on the same listener) | project |
| SEPP FQDN convention | `sepp.5gc.mnc<MNC3>.mcc<MCC>.3gppnetwork.org` (MNC zero-padded to 3 digits, e.g. 001/02 → `sepp.5gc.mnc002.mcc001.3gppnetwork.org`). The `5gc.mnc…mcc…3gppnetwork.org` part is the Home Network Domain of TS 23.003 §28.2; the `sepp.` label is a project convention, a partner may use another label (set `n32.sepp_fqdn`) | TS 23.003 §28.2, §28.5.1 |
| N32 certificate SAN | DNS SAN = the SEPP FQDN **and** `*.<SEPP FQDN>` (wildcard for telescopic FQDNs). The PLMN identity of the peer is read from SAN names ending in `mnc<3 digits>.mcc<3 digits>.3gppnetwork.org`; a cert without such a name is rejected | TS 23.003 §28.5.2; TS 33.501 §13.1.1.1, §13.1.2 |
| Certificate EKU | serverAuth + clientAuth (the same cert is used as client and server) | project |
| Trust model | One trust anchor (CA bundle) **per partner PLMN**. Each side gives the other its **N32 CA bundle**. A cert of PLMN B never verifies on the anchor of PLMN A. The local SBI CA is never trusted on N32 | TS 33.501 §13.1.2 |
| N32-c API | `POST /n32c-handshake/v1/exchange-capability`; apiFullVersion **1.2.1** (rel17 profile, TS 29.573 V17.x) or **1.4.1** (rel19 profile, V19.7.0); `apiVersionInUri` `v1` in both | TS 29.573 §6.1 |
| supportedFeatures | rel17: `NFTLST` (`"1"`). rel19: `NFTLST` + `PSIU` (`"5"`). `NFTLST` is needed for the `NONE` teardown | TS 29.573 Table 6.1.7-1 |
| 3gpp-Sbi-Target-apiRoot | Supported and signalled (`3GppSbiTargetApiRootSupported: true`). If the partner does not support it, the sending SEPP rewrites the request URI to the target apiRoot | TS 29.500 §6.1.4.3 |
| Purposes | Accepted: `ROAMING`, `INTER_PLMN_MOBILITY`, `ROAMING_TEST`, `INTER_PLMN_MOBILITY_TEST`. No purposes sent = Roaming + inter-PLMN mobility. All purposes rejected → `403 REQUESTED_PURPOSE_NOT_ALLOWED` | TS 29.573 §5.2.2, Tables 6.1.5.3.9-1, 6.1.6.3-1 |
| Handshake identity checks | `plmnIdList` must match the cert PLMN; `targetPlmnId` (if sent) must be the local PLMN; `sender` must end in the Home Network Domain of the cert PLMN | TS 29.573 §5.2.2, §6.1.5.2 |
| Home NFs | For roaming registration the local AMF needs the partner AUSF and UDM apiRoots (`home_nfs`); NRF inter-PLMN discovery is not used yet (follow-up) | TS 29.510 §5.3.2.2.3 |

## 2. What to exchange with the partner

| You send the partner | The partner sends you |
|---|---|
| Your PLMN (MCC/MNC) | Their PLMN (MCC/MNC) |
| `pki/n32/local/ca.crt` (your N32 CA bundle, **not** `pki/ca.crt`) | Their N32 CA bundle |
| Your SEPP FQDN and reachable `host:8443` | Their SEPP FQDN and N32 `host:port` |
| Release profile (rel17 / rel19) | Their supported TS 29.573 version and features |
| — | Their AUSF and UDM apiRoots (if your AMF serves their subscribers as roamers) |

Keep private keys local; only CA certificates are exchanged.

## 3. Checklist (copy-paste)

Replace `MCC=001 MNC=02` with the partner PLMN.

```bash
# 1. Generate the N32 PKI of the local core (separate from the SBI CA)
make pki            # creates pki/n32/local/{ca,sepp}.{crt,key}
openssl x509 -in pki/n32/local/sepp.crt -noout -ext subjectAltName   # expect sepp.5gc.mnc…  and *.sepp.5gc.mnc…

# 2. Drop the partner N32 CA in place
MCC=001 MNC=02
mkdir -p pki/n32/peers/${MCC}-${MNC}
cp /path/from/partner/n32-ca.crt pki/n32/peers/${MCC}-${MNC}/ca.crt

# 3. Add the partner to config/roaming/partners.yaml (start from partners.example.yaml).
#    If the file already exists, append only the list item under the existing `partners:` key.
cat > config/roaming/partners.yaml <<'EOF'
partners:
  - plmn: {mcc: "001", mnc: "02"}
    n32:
      ca_file: /etc/5gc/pki/n32/peers/001-02/ca.crt
      sepp_fqdn: sepp.5gc.mnc002.mcc001.3gppnetwork.org
      address: sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443
    home_nfs:
      ausf_api_root: https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002
      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003
EOF
#    (or point ROAMING_PARTNERS_FILE at another file, or use the portal Roaming (N32) page)

# 4. Restart SEPP and AMF (the file is read at startup only)
docker compose restart sepp amf

# 5. Verify
curl -s http://localhost:9115/admin/v1/n32/partners | jq      # partner listed, source "file"
curl -s http://localhost:9115/admin/v1/n32/contexts | jq      # N32 context for 001-02, TLS
curl -s http://localhost:9115/metrics | grep -E 'fivegc_sepp_n32c_context_established|fivegc_sepp_n32_tls_reject_total'
```

Expected: `fivegc_sepp_n32c_context_established{peer_plmn="001-02"} 1`, no growth of
`fivegc_sepp_n32_tls_reject_total`. The portal Roaming (N32) page shows the same data. Host ports
depend on your compose mapping.

If the partner is unreachable or rejects: check `fivegc_sepp_n32_tls_reject_total{reason}`
(`no_plmn`, `not_partner`, `anchor_conflict`, `chain`, `plmn_mismatch`) and the `sepp` logs with
`procedure=N32Handshake`.

## 4. Connecting two ClaudIA 5GC cores

Each core runs `make pki` with its own `config/operator.yaml` PLMN, exchanges
`pki/n32/local/ca.crt` with the other side, and adds the other PLMN to its own
partners file (`config/roaming/`). Only one side needs `n32.address` to initiate; setting it on both is
fine (each N32-c context is per PLMN pair). Both cores must agree on the release profile only for
the features they expect; a rel17 and a rel19 core interwork with `NFTLST`.

## 5. Not supported

- PRINS / N32-f application-layer security and Roaming Intermediaries.
- SNPN peers.
- Hot reload of partners (restart required).
- NRF inter-PLMN discovery.
