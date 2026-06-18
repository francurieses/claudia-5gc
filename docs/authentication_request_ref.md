# UERANSIM v3.2.8 — Authentication Request (0x56) Decoding Reference

## Quick Facts

| Item | Value |
|------|-------|
| Message Type | 0x56 (Authentication Request) |
| Error Source | `src/lib/nas/encode.cpp:236` |
| Error Message | "Bad constructed NAS message" |
| Decoder | `DecodeViaBuilder<AuthenticationRequest>()` |
| Root Cause | Unrecognized optional IE in stream after mandatory IEs |

## Message Structure

### Mandatory IEs (MUST be present in this order)

```
Byte 3: ngKSI (4-bit, Type-1 IE)
        High nibble = ngKSI value (0-15)
        Low nibble = spare (must be 0 or ignored)
        
Bytes 4+: ABBA (Variable-length, Type-4 IE)
         Byte 4 = length
         Bytes 5 to (4+length) = data
```

### Optional IEs (Can appear in any order, all are Type-4 with length field)

| IEI | Meaning | Format |
|-----|---------|--------|
| 0x21 | Authentication Parameter RAND | `[0x21][len:1byte][data:len bytes]` |
| 0x20 | Authentication Parameter AUTN | `[0x20][len:1byte][data:len bytes]` |
| 0x78 | EAP Message | `[0x78][len:1byte][data:len bytes]` |

## Error Trigger

The error **"Bad constructed NAS message"** is thrown when:

```cpp
while (stream.hasNext())
{
    int iei = stream.peekI();
    if (builder.optionalDecoders.count(iei))
        builder.optionalDecoders[iei](stream);
    else if (builder.optionalDecoders.count((iei >> 4) & 0xF))
        builder.optionalDecoders[(iei >> 4) & 0xF](stream);
    else
        throw std::runtime_error("Bad constructed NAS message");  // ← HERE
}
```

**Condition**: After decoding mandatory IEs, there's a byte in the stream that:
- Is NOT equal to 0x21, 0x20, or 0x78
- AND is NOT a valid Type-1 IE (high nibble not in decoders table)

## Example Valid Message (hex dump)

```
7E 00 56       <- EPD (0x7E), SHT+SN (0x00), MsgType (0x56)
62             <- ngKSI=6 (0x6 in high nibble), spare=2
04 AA BB CC DD <- ABBA: length=4, data=[AA,BB,CC,DD]
21 10          <- IEI 0x21 (RAND), length=16
[16 bytes of RAND]
20 10          <- IEI 0x20 (AUTN), length=16
[16 bytes of AUTN]
```

**Total**: 3 + 1 + 1 + 4 + 1 + 1 + 16 + 1 + 1 + 16 = 45 bytes

## Common Mistakes to Avoid

❌ **Extra padding bytes** after the last optional IE  
✅ Send exact length, no padding

❌ **Unknown IEI values** (e.g., 0x7F, 0xFF)  
✅ Only use 0x21, 0x20, 0x78

❌ **Wrong ngKSI encoding** (use low nibble instead of high)  
✅ ngKSI must be in HIGH nibble: `(ngKSI << 4)`

❌ **Incorrect ABBA length** (length doesn't match actual data)  
✅ Length byte must equal actual data bytes that follow

❌ **RAND/AUTN not exactly 16 bytes each**  
✅ Per TS 24.501, RAND and AUTN are fixed 16 bytes

❌ **Reordering mandatory IEs**  
✅ ngKSI must come before ABBA

## Code Path Summary

```
DecodeNasMessage()
  ↓ reads EPD (0x7E)
  ↓ reads SHT+SN
  ↓ reads msgType (0x56)
  ↓
DecodePlainMmMessage(stream, 0x56)
  ↓
DecodeViaBuilder<AuthenticationRequest>(stream)
  ├─ Mandatory: decode ngKSI
  ├─ Mandatory: decode ABBA
  └─ Optional loop:
     ├─ Read next byte as IEI
     ├─ Check: IEI ∈ {0x21, 0x20, 0x78}?
     ├─ Check: (IEI >> 4) ∈ optional decoders?
     └─ ELSE → THROW "Bad constructed NAS message"
```

## Files in UERANSIM Source

- **Definition**: `src/lib/nas/msg.hpp` (struct AuthenticationRequest)
- **Build spec**: `src/lib/nas/msg.cpp` (AuthenticationRequest::onBuild)
- **Decoder**: `src/lib/nas/encode.cpp` (DecodeViaBuilder, DecodeViaBuilder<AuthenticationRequest>, DecodePlainMmMessage)
- **IE types**: `src/lib/nas/base.hpp` (IE1-IE6 encoding/decoding)
- **Enums**: `src/lib/nas/enums.hpp` (EMessageType::AUTHENTICATION_REQUEST = 0x56)

## 3GPP References

| Reference | Meaning |
|-----------|---------|
| TS 24.501 | NAS 5GS protocol |
| TS 24.501 §9.1.1.1 | Authentication Request message structure |
| TS 29.571 | Common types for SBA (RAND, AUTN, ngKSI definitions) |

