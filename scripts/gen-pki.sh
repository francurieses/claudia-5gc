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

NFS=(nrf amf smf upf ausf udm udr pcf nssf smsf nef bsf lmf mcp mgmt-portal sepp hsepp hnrf hausf hudm hudr hsmf)

# SEPP N32 identities (TS 23.003 §28.5.2, TS 33.501 §13.1): the SEPP FQDN is
# sepp.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org; the wildcard covers the
# telescopic FQDNs (<nf-fqdn-with-hyphens>.<seppfqdn>, one label).
# sepp = local core (PLMN from config/operator.yaml, default 001/01), hsepp = test peer (PLMN 001/02).
sepp_fqdn() {
  case "$1" in
    sepp)  echo "sepp.5gc.mnc${LOCAL_MNC3}.mcc${LOCAL_MCC}.3gppnetwork.org" ;;
    hsepp) echo "sepp.5gc.mnc002.mcc001.3gppnetwork.org" ;;
    hnrf)  echo "nrf.5gc.mnc002.mcc001.3gppnetwork.org" ;;
    # Home-PLMN core subset for roaming (ROAM-001): the hSEPP dials these FQDNs
    # (TS 23.003 §28.5.1); the short names hausf/hudm/hudr are DNS.2.
    hausf) echo "ausf.5gc.mnc002.mcc001.3gppnetwork.org" ;;
    hudm)  echo "udm.5gc.mnc002.mcc001.3gppnetwork.org" ;;
    hudr)  echo "udr.5gc.mnc002.mcc001.3gppnetwork.org" ;;
    # Home SMF for home-routed PDU sessions (ROAM-002); short name hsmf is DNS.2.
    hsmf)  echo "smf.5gc.mnc002.mcc001.3gppnetwork.org" ;;
  esac
}

# Local PLMN from config/operator.yaml (`plmn:` block); MNC zero-padded to 3 digits.
ROOT="$(dirname "$PKI")"
read_plmn() {
  awk -v k="$1" '/^plmn:/{f=1;next} f&&/^[^ \t#]/{f=0} f&&$1==k":"{gsub(/["\047]/,"",$2);print $2;exit}' \
    "$ROOT/config/operator.yaml" 2>/dev/null || true
}
LOCAL_MCC="$(read_plmn mcc)"; LOCAL_MCC="${LOCAL_MCC:-001}"
LOCAL_MNC="$(read_plmn mnc)"; LOCAL_MNC="${LOCAL_MNC:-01}"
LOCAL_MNC3="$(printf '%03d' "$((10#$LOCAL_MNC))")"

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

# ---- N32 PKI (SEPP-004) -------------------------------------------------
# Separate N32 CAs per PLMN, independent of the SBI CA above: the SEPP trusts a
# partner only through the anchor in pki/n32/peers/<mcc>-<mnc>/ca.crt
# (TS 33.501 §13.2). Leaf SAN carries the SEPP FQDN (TS 23.003 §28.5.2) and the
# telescopic wildcard; EKU serverAuth+clientAuth (N32 is mutual TLS).
n32_ca() { # dir label
  local d="$1"
  mkdir -p "$d"
  if [ ! -f "$d/ca.key" ] || [ ! -f "$d/ca.crt" ]; then
    echo "==> generating N32 CA $d"
    openssl genrsa -out "$d/ca.key" "$KEY_BITS"
    chmod 0644 "$d/ca.key"
    openssl req -x509 -new -nodes -key "$d/ca.key" -sha256 -days $((DAYS*2)) \
      -subj "/C=ES/O=5GC-Dev/CN=5gc-dev-n32-ca-$2" -out "$d/ca.crt"
  fi
}
n32_leaf() { # dir fqdn
  local d="$1" fqdn="$2"
  if [ -f "$d/sepp.key" ] && [ -f "$d/sepp.crt" ]; then
    return 0
  fi
  echo "==> generating N32 cert $d/sepp ($fqdn)"
  openssl genrsa -out "$d/sepp.key" "$KEY_BITS"
  chmod 0644 "$d/sepp.key"
  cat > "$d/sepp.cnf" <<EOF
[ req ]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[ req_dn ]
C  = ES
O  = 5GC-Dev
CN = $fqdn

[ alt_names ]
DNS.1 = $fqdn
DNS.2 = *.$fqdn

[ v3_req ]
basicConstraints  = CA:FALSE
keyUsage          = digitalSignature, keyEncipherment
extendedKeyUsage  = serverAuth, clientAuth
subjectAltName    = @alt_names
EOF
  openssl req -new -key "$d/sepp.key" -out "$d/sepp.csr" -config "$d/sepp.cnf"
  openssl x509 -req -in "$d/sepp.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial \
    -out "$d/sepp.crt" -days "$DAYS" -sha256 -extensions v3_req -extfile "$d/sepp.cnf"
  rm -f "$d/sepp.csr" "$d/sepp.cnf" "$d/ca.srl"
}

n32_ca n32/local "$LOCAL_MCC-$LOCAL_MNC3"
n32_leaf n32/local "sepp.5gc.mnc${LOCAL_MNC3}.mcc${LOCAL_MCC}.3gppnetwork.org"
n32_ca n32/testpeer "001-002"
n32_leaf n32/testpeer "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
# Partner trust anchors of the local core: the test peer (PLMN 001/02).
mkdir -p n32/peers/001-02
cp -f n32/testpeer/ca.crt n32/peers/001-02/ca.crt

echo
echo "PKI ready in $PKI"
ls -1 "$PKI" | sed 's/^/  /'
