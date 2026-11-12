#!/usr/bin/env bash
# scripts/gen-pki.sh
# Genera una CA local y un cert/key por NF para TLS mutuo en SBA (TS 33.501 §13).
# Uso: ./scripts/gen-pki.sh
#
# Requiere openssl. Idempotente: si ya existen, no regenera.

set -euo pipefail

PKI="$(cd "$(dirname "$0")/.." && pwd)/pki"
DAYS=825
KEY_BITS=4096

NFS=(nrf amf smf upf ausf udm udr pcf nssf smsf nef bsf lmf mcp mgmt-portal vsepp hsepp hnrf)

# SEPP N32 identities (TS 23.003 §28.5.2, TS 33.501 §13.1): the SEPP FQDN is
# sepp.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org; the wildcard covers the
# telescopic FQDNs (<nf-fqdn-with-hyphens>.<seppfqdn>, one label).
# vsepp = visited PLMN 001/001, hsepp = home PLMN 001/002.
sepp_fqdn() {
  case "$1" in
    vsepp) echo "sepp.5gc.mnc001.mcc001.3gppnetwork.org" ;;
    hsepp) echo "sepp.5gc.mnc002.mcc001.3gppnetwork.org" ;;
    hnrf)  echo "nrf.5gc.mnc002.mcc001.3gppnetwork.org" ;;
  esac
}

mkdir -p "$PKI"
cd "$PKI"

# ---- CA -----------------------------------------------------------------
if [ ! -f ca.key ]; then
  echo "==> generating CA"
  openssl genrsa -out ca.key "$KEY_BITS"
  chmod 644 ca.key
  openssl req -x509 -new -nodes -key ca.key -sha256 -days $((DAYS*2)) \
    -subj "/C=ES/O=5GC-Dev/CN=5gc-dev-ca" \
    -out ca.crt
fi

for nf in "${NFS[@]}"; do
  if [ -f "$nf.key" ] && [ -f "$nf.crt" ]; then
    continue
  fi
  echo "==> generating cert for $nf"
  openssl genrsa -out "$nf.key" "$KEY_BITS"
  # Newer openssl writes keys 0600; NF containers run as nonroot and bind-mount
  # the key read-only, so make it world-readable (dev PKI — matches the existing
  # keys in pki/). Without this the container gets "permission denied" on the key.
  chmod 0644 "$nf.key"

  extra_sans=""
  fqdn="$(sepp_fqdn "$nf")"
  if [ -n "$fqdn" ]; then
    extra_sans="DNS.4 = $fqdn
DNS.5 = *.$fqdn"
  fi

  cat > "$nf.cnf" <<EOF
[ req ]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[ req_dn ]
C  = ES
O  = 5GC-Dev
CN = $nf.5gc.local

[ alt_names ]
DNS.1 = $nf.5gc.local
DNS.2 = $nf
DNS.3 = localhost
$extra_sans
IP.1  = 127.0.0.1

[ v3_req ]
basicConstraints  = CA:FALSE
keyUsage          = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage  = serverAuth, clientAuth
subjectAltName    = @alt_names
EOF

  openssl req -new -key "$nf.key" -out "$nf.csr" -config "$nf.cnf"
  openssl x509 -req -in "$nf.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$nf.crt" -days "$DAYS" -sha256 \
    -extensions v3_req -extfile "$nf.cnf"
  rm -f "$nf.csr" "$nf.cnf"
done

echo
echo "PKI ready in $PKI"
ls -1 "$PKI" | sed 's/^/  /'
