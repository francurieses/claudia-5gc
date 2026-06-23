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

NFS=(nrf amf smf upf ausf udm udr pcf nssf smsf scp nef chf bsf lmf mcp mgmt-portal)

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
