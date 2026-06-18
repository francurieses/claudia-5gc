# Authentication Request (0x56) — Byte-by-Byte Encoding for AMF

## Overall Structure

The Authentication Request sent from AMF to UE (via N1 on NGAP) consists of:

```
[NAS Header: 3 bytes][Message Body: N bytes]
```

### Header (3 bytes) — Shared across ALL 5GMM messages

```
Byte 0: Extended Protocol Discriminator (EPD)
        0x7E = Mobility Management Messages

Byte 1: Security Header Type (SHT) + Sequence Number (SN)
        High nibble (bits 7-4) = SHT
        Low nibble (bits 3-0) = SN
        
        For PLAIN (unencrypted) message: 0x00
        Bit pattern: [0000][0000]
                     ↑ SHT=NOT_PROTECTED
                           ↑ SN=0 (or value)

Byte 2: Message Type
        0x56 = Authentication Request
```

### Example: Plain Authentication Request header
```
Byte 0: 0x7E    (EPD for 5GMM)
Byte 1: 0x00    (Not protected, SN=0)
Byte 2: 0x56    (Authentication Request)
```

---

## Message Body

### Mandatory IEs (in order)

#### IE1: ngKSI (4 bits)

Location in byte stream: **Byte 3, HIGH nibble**

Encoding:
```c
uint8_t byte3 = (ngKSI << 4) | 0x00;  // ngKSI in high nibble, spare=0
```

Example: ngKSI = 6
```
Byte 3: 0x60    (binary 0110|0000)
        ↑ ngKSI=6
         ↑ spare=0
```

**Valid range**: ngKSI ∈ [0, 15]

---

#### IE2: ABBA (Type-4, variable length)

ABBA = Authentication-Binding-Anchoring value (typically random bytes)

Encoding:
```
Byte 4: Length of ABBA (1 byte)
Bytes 5 to (4 + length): ABBA data
```

**Note**: ABBA is typically 8 bytes (64 bits), but length can vary per implementation.

Example: ABBA = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22] (8 bytes)
```
Byte 4: 0x08    (length = 8)
Byte 5: 0xAA
Byte 6: 0xBB
Byte 7: 0xCC
Byte 8: 0xDD
Byte 9: 0xEE
Byte 10: 0xFF
Byte 11: 0x11
Byte 12: 0x22
```

---

### Optional IEs (in any order)

#### Optional IE 0x21: Authentication Parameter RAND

RAND = Authentication Random Challenge (128 bits / 16 bytes, per TS 24.501 §9.1.1.1)

Encoding:
```
Byte N: 0x21 (IEI)
Byte N+1: 0x10 (Length = 16 bytes, FIXED)
Bytes N+2 to N+17: RAND value (16 bytes)
```

Example:
```
Byte 45: 0x21    (IEI identifier)
Byte 46: 0x10    (Length = 16)
Bytes 47-62: [16 bytes of RAND from UDR/AUSF]
```

**Critical**: RAND MUST be exactly 16 bytes per 3GPP TS 33.501 / TS 24.501.

---

#### Optional IE 0x20: Authentication Parameter AUTN

AUTN = Authentication Token (128 bits / 16 bytes, per TS 24.501 §9.1.1.1)

Encoding:
```
Byte M: 0x20 (IEI)
Byte M+1: 0x10 (Length = 16 bytes, FIXED)
Bytes M+2 to M+17: AUTN value (16 bytes)
```

Example:
```
Byte 63: 0x20    (IEI identifier)
Byte 64: 0x10    (Length = 16)
Bytes 65-80: [16 bytes of AUTN from AUSF]
```

**Critical**: AUTN MUST be exactly 16 bytes per 3GPP TS 33.501 / TS 24.501.

---

#### Optional IE 0x78: EAP Message (Rarely used for 5G-AKA)

EAP message (Extensible Authentication Protocol, typically for EAP-AKA or fallback).

Encoding:
```
Byte P: 0x78 (IEI)
Byte P+1: Length (1 byte)
Bytes P+2 to (P+1+length): EAP data
```

For most 5G-AKA scenarios, this is **omitted** (EAP is used only in fallback cases).

---

## Complete Example Message

### Inputs

```
ngKSI = 1
ABBA = [0x00, 0x00, 0x00, 0x01] (4 bytes)
RAND = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99] (16 bytes)
AUTN = [0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
        0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA] (16 bytes)
EAP = (omitted)
```

### Hex Dump

```
Offset  Hex Value    Description
──────────────────────────────────────────────────────────
0x00    7E           EPD (5GMM)
0x01    00           SHT (not protected) + SN (0)
0x02    56           Message Type (Authentication Request)
0x03    10           ngKSI=1 (0001|0000), spare=0
0x04    04           ABBA length = 4
0x05    00           ABBA[0]
0x06    00           ABBA[1]
0x07    00           ABBA[2]
0x08    01           ABBA[3]
0x09    21           IEI: RAND
0x0A    10           RAND length = 16
0x0B    AA           RAND[0]
0x0C    BB           RAND[1]
0x0D    CC           RAND[2]
0x0E    DD           RAND[3]
0x0F    EE           RAND[4]
0x10    FF           RAND[5]
0x11    00           RAND[6]
0x12    11           RAND[7]
0x13    22           RAND[8]
0x14    33           RAND[9]
0x15    44           RAND[10]
0x16    55           RAND[11]
0x17    66           RAND[12]
0x18    77           RAND[13]
0x19    88           RAND[14]
0x1A    99           RAND[15]
0x1B    20           IEI: AUTN
0x1C    10           AUTN length = 16
0x1D    99           AUTN[0]
0x1E    88           AUTN[1]
0x1F    77           AUTN[2]
0x20    66           AUTN[3]
0x21    55           AUTN[4]
0x22    44           AUTN[5]
0x23    33           AUTN[6]
0x24    22           AUTN[7]
0x25    11           AUTN[8]
0x26    00           AUTN[9]
0x27    FF           AUTN[10]
0x28    EE           AUTN[11]
0x29    DD           AUTN[12]
0x2A    CC           AUTN[13]
0x2B    BB           AUTN[14]
0x2C    AA           AUTN[15]

Total: 45 bytes (0x2D bytes)
```

---

## UERANSIM Decoding (What UERANSIM Expects)

When UERANSIM receives the above 45-byte message:

1. **Reads bytes 0-2**: Parses EPD, SHT, message type → routes to `DecodePlainMmMessage(0x56)`

2. **Calls `DecodeViaBuilder<AuthenticationRequest>`** on bytes 3-44:
   - Calls `AuthenticationRequest::onBuild(builder)` → registers mandatory and optional decoders
   - Decodes **ngKSI** from byte 3, high nibble
   - Decodes **ABBA** starting at byte 4 (reads length, then data)
   - Loops through remaining bytes:
     - Byte 0x09 = 0x21 → found in optionalDecoders → decode RAND
     - Byte 0x1B = 0x20 → found in optionalDecoders → decode AUTN
     - No more bytes → exit loop

3. **Returns** populated `AuthenticationRequest` struct to UE

4. **Error scenario**: If extra unrecognized byte at end → **"Bad constructed NAS message"** at `encode.cpp:236`

---

## When Security is Applied (SHT != 0x00)

If the AMF sends the message with NAS security (ciphering + integrity check):

```
Byte 0: EPD (0x7E)
Byte 1: SHT (0x01-0x04, depending on integrity/ciphering) + SN
Byte 2: Message Type (0x56)
Bytes 3-6: MAC (Message Authentication Code, 4 bytes)
Byte 7: Sequence Number (for NAS security context)
Bytes 8+: ENCRYPTED payload (plaintext structure + ciphering)
```

But the **plaintext inner structure** (bytes 3+ in the example) remains the same, it's just encrypted and wrapped with MAC.

For UERANSIM to decrypt:
- It must have the NAS security context (keys K_nas_int, K_nas_enc)
- It must know the algorithm (NIA2, NEA2)
- It must have the UL/DL count

---

## Checklist for Your AMF Implementation

When encoding Authentication Request:

- [ ] EPD byte is 0x7E
- [ ] SHT + SN byte matches your security context (usually 0x00 for initial)
- [ ] Message type is 0x56
- [ ] ngKSI is in HIGH nibble of byte 3, range [0-15]
- [ ] ABBA length byte matches actual data length
- [ ] If RAND included: IEI=0x21, length=0x10, data=16 bytes
- [ ] If AUTN included: IEI=0x20, length=0x10, data=16 bytes
- [ ] No padding or extra bytes after last IE
- [ ] No unknown IEI values
- [ ] Total message length matches NAS PDU length in NGAP container

