#!/usr/bin/env python3
"""
decode-ursp.py — Decode a UE policy container (MANAGE UE POLICY COMMAND) from
base64 or hex.

This decodes the bytes the PCF returns in the N15 response and that the AMF
carries in a DL NAS TRANSPORT message with payload container type = "UE policy
container" (0x05). The structure is verified against TS 24.501 Annex D and
TS 24.526 §5.2/§5.3 (matching the Wireshark NAS-5GS dissector).

Usage:
  # From PCF N15 JSON (pipe the API response):
  docker exec amf curl -sk --http2-prior-knowledge \\
    -X POST https://pcf:8006/npcf-ue-policy-control/v1/ue-policies \\
    -H 'Content-Type: application/json' \\
    -d '{"supi":"imsi-001010000000001","servingPlmn":"00101"}' | \\
    python3 scripts/decode-ursp.py

  # From raw base64 string:
  python3 scripts/decode-ursp.py --b64 "<base64_string>"

  # From hex string:
  python3 scripts/decode-ursp.py --hex "8001 002e ..."

Ref: TS 24.501 Annex D (UE policy delivery service), TS 24.526 §5.2/§5.3
"""

import sys
import json
import struct
import base64
import argparse

# ---- Type code tables ---------------------------------------------------

# Traffic descriptor component types (TS 24.526 §5.2, Table 5.2.1).
UPDS_MSG_TYPES = {
    0x01: "MANAGE UE POLICY COMMAND",
    0x02: "MANAGE UE POLICY COMPLETE",
    0x03: "MANAGE UE POLICY COMMAND REJECT",
    0x04: "UE STATE INDICATION",
    0x05: "UE POLICY PROVISIONING REQUEST",
    0x06: "UE POLICY PROVISIONING REJECT",
}

UE_POLICY_PART_TYPES = {0x01: "URSP", 0x02: "ANDSP"}

CONN_CAPS = {0x01: "IMS", 0x02: "MMS", 0x04: "SUPL", 0x08: "Internet"}

PDU_SESSION_TYPES = {1: "IPv4", 2: "IPv6", 3: "IPv4v6", 4: "Unstructured", 5: "Ethernet"}
SSC_MODES = {1: "SSC Mode 1", 2: "SSC Mode 2", 3: "SSC Mode 3"}


# ---- Low-level helpers --------------------------------------------------

def u16(b, i):
    return struct.unpack(">H", b[i:i + 2])[0]


def decode_apn(data: bytes) -> str:
    """Decode an APN/DNN/FQDN in label format (TS 23.003 §9.1): length-prefixed labels."""
    labels = []
    i = 0
    while i < len(data):
        ln = data[i]
        i += 1
        if ln == 0 or i + ln > len(data):
            break
        labels.append(data[i:i + ln].decode("utf-8", "replace"))
        i += ln
    return ".".join(labels) if labels else data.decode("utf-8", "replace")


def decode_snssai(data: bytes) -> str:
    if len(data) == 1:
        return f"SST={data[0]}"
    if len(data) >= 4:
        return f"SST={data[0]}, SD={data[1:4].hex()}"
    return data.hex()


def decode_plmn(b: bytes) -> str:
    """Decode a 3-byte PLMN identity per TS 24.008 §10.5.1.13."""
    if len(b) < 3:
        return b.hex()
    mcc_d1, mcc_d2 = b[0] & 0x0F, (b[0] >> 4) & 0x0F
    mcc_d3, mnc_d3 = b[1] & 0x0F, (b[1] >> 4) & 0x0F
    mnc_d1, mnc_d2 = b[2] & 0x0F, (b[2] >> 4) & 0x0F
    mcc = f"{mcc_d1}{mcc_d2}{mcc_d3}"
    mnc = f"{mnc_d1}{mnc_d2}" if mnc_d3 == 0xF else f"{mnc_d1}{mnc_d2}{mnc_d3}"
    return f"MCC={mcc} MNC={mnc}"


# ---- Traffic descriptor (TS 24.526 §5.2) --------------------------------

def decode_traffic_descriptor(raw: bytes) -> list[str]:
    """Decode traffic descriptor components. Components carry no generic length
    octet; each type identifier implies a fixed or self-describing value."""
    parts = []
    i = 0
    while i < len(raw):
        t = raw[i]
        i += 1
        if t == 0x01:
            parts.append("match-all")
            break
        elif t == 0x08:  # OS Id + OS App Id
            os_id = raw[i:i + 16]; i += 16
            ln = raw[i]; i += 1
            app = raw[i:i + ln]; i += ln
            parts.append(f"os-app(os={os_id.hex()}, app={app.decode('utf-8','replace')})")
        elif t == 0x10:  # IPv4 remote address + mask
            addr, mask = raw[i:i + 4], raw[i + 4:i + 8]; i += 8
            prefix = bin(struct.unpack(">I", mask)[0]).count("1")
            parts.append(f"IPv4={addr[0]}.{addr[1]}.{addr[2]}.{addr[3]}/{prefix}")
        elif t == 0x21:  # IPv6 remote address/prefix
            addr = raw[i:i + 16]; i += 16
            plen = raw[i]; i += 1
            parts.append(f"IPv6={addr.hex()}/{plen}")
        elif t == 0x30:  # protocol id / next header
            parts.append(f"proto={raw[i]}"); i += 1
        elif t == 0x50:  # single remote port
            parts.append(f"port={u16(raw, i)}"); i += 2
        elif t == 0x51:  # remote port range
            parts.append(f"ports={u16(raw, i)}-{u16(raw, i + 2)}"); i += 4
        elif t == 0x60:  # security parameter index
            parts.append(f"spi={raw[i:i+4].hex()}"); i += 4
        elif t == 0x70:  # type of service / traffic class
            parts.append(f"tos={raw[i:i+2].hex()}"); i += 2
        elif t == 0x80:  # flow label
            parts.append(f"flow-label={raw[i:i+3].hex()}"); i += 3
        elif t == 0x90:  # connection capabilities
            n = raw[i]; i += 1
            caps = [CONN_CAPS.get(raw[i + k], f"{raw[i + k]:#04x}") for k in range(n)]
            i += n
            parts.append(f"conn-cap={'|'.join(caps)}")
        elif t == 0x91:  # destination FQDN
            ln = raw[i]; i += 1
            parts.append(f"FQDN={decode_apn(raw[i:i + ln])}"); i += ln
        elif t == 0xa0:  # OS App Id
            ln = raw[i]; i += 1
            parts.append(f"os-app-id={raw[i:i + ln].decode('utf-8','replace')}"); i += ln
        else:
            parts.append(f"type={t:#04x}(rest={raw[i:].hex()})")
            break
    return parts


# ---- Route selection descriptor (TS 24.526 §5.3) ------------------------

def decode_rsd_contents(raw: bytes) -> list[str]:
    comps = []
    i = 0
    while i < len(raw):
        t = raw[i]
        i += 1
        if t == 0x01:  # SSC mode (1 octet, no length)
            comps.append(f"SSC={SSC_MODES.get(raw[i] & 0x07, raw[i])}"); i += 1
        elif t == 0x02:  # S-NSSAI (length + value)
            ln = raw[i]; i += 1
            comps.append(f"S-NSSAI={decode_snssai(raw[i:i + ln])}"); i += ln
        elif t == 0x04:  # DNN (length + value)
            ln = raw[i]; i += 1
            comps.append(f"DNN={decode_apn(raw[i:i + ln])}"); i += ln
        elif t == 0x08:  # PDU session type (1 octet, no length)
            comps.append(f"PDU-type={PDU_SESSION_TYPES.get(raw[i] & 0x07, raw[i])}"); i += 1
        elif t == 0x10:  # preferred access type (1 octet, no length)
            acc = {1: "3GPP", 2: "non-3GPP", 3: "3GPP+non-3GPP"}.get(raw[i] & 0x03, raw[i])
            comps.append(f"access={acc}"); i += 1
        else:
            comps.append(f"type={t:#04x}(rest={raw[i:].hex()})")
            break
    return comps


def decode_rsd_list(raw: bytes) -> list[dict]:
    """Each RSD: length(2) | precedence(1) | contents length(2) | contents."""
    rsds = []
    i = 0
    while i + 2 <= len(raw):
        rsd_len = u16(raw, i); i += 2
        body = raw[i:i + rsd_len]; i += rsd_len
        if len(body) < 3:
            break
        prec = body[0]
        clen = u16(body, 1)
        contents = body[3:3 + clen]
        rsds.append({"precedence": prec, "components": decode_rsd_contents(contents)})
    return rsds


def decode_ursp_rules(raw: bytes) -> list[dict]:
    """Each URSP rule: length(2) | precedence(1) | TD length(2) | TD |
    RSD list length(2) | RSD list (TS 24.526 §5.2)."""
    rules = []
    i = 0
    while i + 2 <= len(raw):
        rule_len = u16(raw, i); i += 2
        body = raw[i:i + rule_len]; i += rule_len
        if len(body) < 5:
            break
        prec = body[0]
        td_len = u16(body, 1)
        j = 3
        td = body[j:j + td_len]; j += td_len
        rsd_len = u16(body, j); j += 2
        rsd = body[j:j + rsd_len]
        rules.append({
            "precedence": prec,
            "traffic_descriptor": decode_traffic_descriptor(td),
            "route_selection_descriptors": decode_rsd_list(rsd),
        })
    return rules


# ---- UE policy container (MANAGE UE POLICY COMMAND, TS 24.501 Annex D) ---

def decode_container(raw: bytes) -> dict:
    """Decode a UE policy container.

    Structure (TS 24.501 §D.5.1 / §D.6.2):
      PTI(1) | message type(1) | section management list length(2) | value
        sublist: length(2) | PLMN(3) | instructions
          instruction: length(2) | UPSC(2) | UE policy parts
            part: length(2) | type(1) | content (URSP rules)
    """
    if len(raw) < 4:
        return {"error": f"container too short: {len(raw)} bytes (want >= 4)"}

    result = {
        "pti": raw[0],
        "message_type": UPDS_MSG_TYPES.get(raw[1], f"unknown({raw[1]:#04x})"),
        "raw_hex": raw.hex(),
        "sublists": [],
    }
    list_len = u16(raw, 2)
    pos = 4
    end = min(pos + list_len, len(raw))

    while pos + 2 <= end:
        sub_len = u16(raw, pos); pos += 2
        sub = raw[pos:pos + sub_len]; pos += sub_len
        if len(sub) < 3:
            break
        sublist = {"plmn": decode_plmn(sub[0:3]), "plmn_hex": sub[0:3].hex(), "instructions": []}

        instr_bytes = sub[3:]
        k = 0
        while k + 2 <= len(instr_bytes):
            ins_len = u16(instr_bytes, k); k += 2
            ins = instr_bytes[k:k + ins_len]; k += ins_len
            if len(ins) < 2:
                break
            instruction = {"upsc": f"{u16(ins, 0):#06x}", "parts": []}
            part_bytes = ins[2:]
            m = 0
            while m + 2 <= len(part_bytes):
                part_len = u16(part_bytes, m); m += 2
                part = part_bytes[m:m + part_len]; m += part_len
                if len(part) < 1:
                    break
                ptype = part[0]
                entry = {"type": UE_POLICY_PART_TYPES.get(ptype, f"unknown({ptype:#04x})")}
                if ptype == 0x01:
                    entry["ursp_rules"] = decode_ursp_rules(part[1:])
                    entry["rule_count"] = len(entry["ursp_rules"])
                else:
                    entry["content_hex"] = part[1:].hex()
                instruction["parts"].append(entry)
            sublist["instructions"].append(instruction)
        result["sublists"].append(sublist)

    return result


# ---- Input sources -------------------------------------------------------

def container_from_n15_response(text: str) -> bytes | None:
    try:
        data = json.loads(text)
        for _, section in data.get("uePolicySections", {}).items():
            content = section.get("uePolicySectionContent", "")
            if content:
                return base64.b64decode(content)
    except Exception:
        pass
    return None


# ---- Printer -------------------------------------------------------------

def print_container(d: dict) -> None:
    if "error" in d:
        print(f"ERROR: {d['error']}")
        return
    nbytes = len(d["raw_hex"]) // 2
    print(f"UE policy container ({nbytes} bytes)")
    print(f"  PTI          : {d['pti']:#04x}")
    print(f"  Message type : {d['message_type']}")
    for si, sub in enumerate(d.get("sublists", [])):
        print(f"  ─── Sublist {si + 1} ({sub['plmn']}, hex={sub['plmn_hex']}) ───")
        for ii, ins in enumerate(sub.get("instructions", [])):
            print(f"    Instruction {ii + 1}  UPSC={ins['upsc']}")
            for pi, part in enumerate(ins.get("parts", [])):
                print(f"      UE policy part {pi + 1}: {part['type']}")
                for ri, rule in enumerate(part.get("ursp_rules", [])):
                    print(f"        URSP rule {ri + 1} (precedence={rule['precedence']})")
                    print(f"          Traffic descriptor: {rule['traffic_descriptor']}")
                    for rsd in rule.get("route_selection_descriptors", []):
                        comps = ", ".join(rsd["components"]) if rsd["components"] else "(empty)"
                        print(f"          Route selection (prec={rsd['precedence']}): {comps}")


# ---- Main ----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Decode a UE policy container (MANAGE UE POLICY COMMAND)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--b64", help="Base64-encoded container bytes")
    group.add_argument("--hex", help="Hex-encoded container bytes")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.b64:
        raw = base64.b64decode(args.b64)
    elif args.hex:
        raw = bytes.fromhex(args.hex.replace(" ", "").replace(":", ""))
    else:
        text = sys.stdin.read()
        raw = container_from_n15_response(text)
        if raw is None:
            try:
                raw = base64.b64decode(text.strip())
            except Exception:
                print("ERROR: provide PCF N15 JSON on stdin, or use --b64 / --hex", file=sys.stderr)
                sys.exit(1)

    decoded = decode_container(raw)
    if args.json:
        print(json.dumps(decoded, indent=2, default=lambda o: o.hex() if isinstance(o, bytes) else o))
    else:
        print_container(decoded)


if __name__ == "__main__":
    main()
