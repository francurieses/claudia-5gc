// Package aka implements the 5G-AKA authentication procedure for the AUSF.
//
// Flow (TS 33.501 §6.1.3.2):
//
//  1. AMF sends Nausf_UEAuthentication_Authenticate Request to AUSF.
//  2. AUSF forwards to UDM to get the 5G HE AV (RAND, XRES*, AUTN, KAUSF).
//  3. AUSF derives XRES* and stores the expected HRES*.
//  4. AUSF returns the 5G SE AV (RAND, HXRES*, AUTN) to the AMF/SEAF.
//  5. AMF sends RAND + AUTN to UE (inside Authentication Request NAS message).
//  6. UE computes RES* and returns it in Authentication Response.
//  7. AMF sends RES* to AUSF as Nausf_UEAuthentication_Authenticate Request (2nd).
//  8. AUSF verifies RES* against stored XRES*, then computes HRES* and compares.
//  9. On success, AUSF returns KAUSF to AMF and notifies UDM.
package aka

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/crypto/milenage"
)

// AuthContext holds state for an ongoing authentication procedure.
// Keyed by authentication session ID at the AUSF.
type AuthContext struct {
	SUPI           string
	SUCI           string
	ServingNetName string
	RAND           [16]byte
	XRES           [8]byte
	XRESStar       []byte // 16 bytes
	HRESStar       []byte // 16 bytes (returned to AMF as HXRES*)
	KAUSF          []byte // 32 bytes
	AUTN           [16]byte
	CreatedAt      time.Time
	Confirmed      bool
}

// AuthStore is the interface for auth context storage.
// Default implementation is in-memory; production deployments use RedisStore.
type AuthStore interface {
	Put(id string, ctx *AuthContext)
	Get(id string) (*AuthContext, bool)
	Delete(id string)
}

// Store is an in-memory session store for auth contexts.
type Store struct {
	mu   sync.Mutex
	ctxs map[string]*AuthContext // key = authCtxID
}

func NewStore() *Store {
	return &Store{ctxs: make(map[string]*AuthContext)}
}

func (s *Store) Put(id string, ctx *AuthContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctxs[id] = ctx
}

func (s *Store) Get(id string) (*AuthContext, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ctxs[id]
	return c, ok
}

func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ctxs, id)
}

// ---- 5G HE AV Generation (UDM side, called by AUSF via Nudm) -----------

// HEAVInput holds the subscriber credentials needed to generate a 5G HE AV.
type HEAVInput struct {
	SUPI string
	K    [16]byte // permanent key
	OPc  [16]byte // operator-variant K
	AMF  [2]byte  // authentication management field
	SQN  [6]byte  // current sequence number
}

// HEAuthVector is the 5G Home Environment Authentication Vector.
// Ref: TS 33.501 §6.1.3.2 step 4.
type HEAuthVector struct {
	RAND  [16]byte
	XRES  [8]byte
	AUTN  [16]byte
	KAUSF []byte // 32 bytes (derived from CK, IK)
}

// GenerateHEAV generates a 5G HE AV from subscriber credentials.
// This is the UDM/ARPF function (TS 33.501 §A.2 + §6.1.3.2 steps 3-4).
func GenerateHEAV(in HEAVInput, snName string) (*HEAuthVector, [6]byte, error) {
	// Generate a fresh random RAND
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return nil, [6]byte{}, fmt.Errorf("aka: rand: %w", err)
	}

	av, ak, err := milenage.GenerateAV(in.K, in.OPc, randBytes, in.SQN, in.AMF)
	if err != nil {
		return nil, [6]byte{}, fmt.Errorf("aka: milenage: %w", err)
	}

	// SQN ⊕ AK (anonymity key)
	var sqnXorAK [6]byte
	for i := 0; i < 6; i++ {
		sqnXorAK[i] = in.SQN[i] ^ ak[i]
	}

	// Derive KAUSF = KDF(CK || IK, SN name || SQN ⊕ AK)
	kausf := kdf.KAUSF(av.CK, av.IK, snName, sqnXorAK)

	// XRES* is not part of this struct — callers needing the full derivation
	// (XRES*, HRES*) use GenerateFull. HEAuthVector holds raw XRES only.
	return &HEAuthVector{
		RAND:  av.RAND,
		XRES:  av.XRES,
		AUTN:  av.AUTN,
		KAUSF: kausf,
	}, sqnXorAK, nil
}

// GenerateHEAVFull returns all derived values needed by AUSF.
type HEAVFull struct {
	RAND     [16]byte
	XRES     [8]byte // original XRES (Milenage f2)
	AUTN     [16]byte
	KAUSF    []byte // 32 bytes
	XRESStar []byte // 16 bytes (XRES*)
	HRESStar []byte // 16 bytes (HRES*) = SHA-256(RAND || XRES*)[16:]
}

// GenerateFull creates a complete 5G HE AV with all AUSF-needed fields.
// Ref: TS 33.501 §6.1.3.2 + Annex A
func GenerateFull(in HEAVInput, snName string) (*HEAVFull, error) {
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return nil, fmt.Errorf("aka: rand: %w", err)
	}

	av, ak, err := milenage.GenerateAV(in.K, in.OPc, randBytes, in.SQN, in.AMF)
	if err != nil {
		return nil, fmt.Errorf("aka: milenage: %w", err)
	}

	var sqnXorAK [6]byte
	for i := 0; i < 6; i++ {
		sqnXorAK[i] = in.SQN[i] ^ ak[i]
	}

	kausf := kdf.KAUSF(av.CK, av.IK, snName, sqnXorAK)
	xresStar := kdf.XRESStar(av.CK, av.IK, snName, av.RAND, av.XRES[:])
	hresStar := kdf.HRESStar(av.RAND, xresStar)

	return &HEAVFull{
		RAND:     av.RAND,
		XRES:     av.XRES,
		AUTN:     av.AUTN,
		KAUSF:    kausf,
		XRESStar: xresStar,
		HRESStar: hresStar,
	}, nil
}

// ---- AUSF Verification (step 8) -----------------------------------------

// VerifyRES verifies the RES* received from the UE via AMF.
// Returns (kausf, nil) on success, or an error on failure.
// Ref: TS 33.501 §6.1.3.2 step 8.
func VerifyRES(ctx *AuthContext, resStar []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("aka: auth context not found")
	}
	if time.Since(ctx.CreatedAt) > 5*time.Minute {
		return nil, errors.New("aka: auth context expired")
	}

	// AUSF verification per TS 33.501 §6.1.3.2 step 8: compare RES* against the
	// stored XRES*. (The HRES*/HXRES* comparison is the SEAF's job at step 7.)
	// hmac.Equal is constant-time — RES* is authentication material and must not
	// leak match length through timing.
	resOK := hmac.Equal(resStar, ctx.XRESStar)
	// Legacy fallback kept for callers that send HRES* instead of RES*:
	// compare SHA-256(RAND||resStar)[16:] against the stored HRES*.
	hresFromUE := kdf.HRESStar(ctx.RAND, resStar)
	hresOK := hmac.Equal(hresFromUE, ctx.HRESStar)
	if !resOK && !hresOK {
		return nil, errors.New("aka: RES* verification failed")
	}

	ctx.Confirmed = true
	return ctx.KAUSF, nil
}

// ---- Helpers -----------------------------------------------------------

// ParseHexKey decodes a hex string into a 16-byte key, validating length.
func ParseHexKey(s string) ([16]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [16]byte{}, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) != 16 {
		return [16]byte{}, fmt.Errorf("expected 16 bytes, got %d", len(b))
	}
	return [16]byte(b), nil
}

// ParseHexSQN decodes a hex SQN string into 6 bytes.
func ParseHexSQN(s string) ([6]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [6]byte{}, fmt.Errorf("sqn hex: %w", err)
	}
	if len(b) != 6 {
		return [6]byte{}, fmt.Errorf("SQN must be 6 bytes, got %d", len(b))
	}
	return [6]byte(b), nil
}

// ParseHexAMF decodes a hex AMF string into 2 bytes.
func ParseHexAMF(s string) ([2]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [2]byte{}, fmt.Errorf("amf hex: %w", err)
	}
	if len(b) != 2 {
		return [2]byte{}, fmt.Errorf("AMF must be 2 bytes, got %d", len(b))
	}
	return [2]byte(b), nil
}

// ResyncFromAUTS recovers SQN_MS from the AUTS sent by the UE on a
// synchronisation failure and verifies the MAC-S.
//
// AUTS format (TS 33.501 §C.2): CONC_SQNMS (6 bytes) || MAC-S (8 bytes).
//   SQN_MS = CONC_SQNMS ⊕ f5*(K, RAND, OPc)
//   MAC-S  = f1*(K, RAND, OPc, SQN_MS, AMF=0x0000)
//
// Returns (SQN_MS, nil) when MAC-S is valid; error otherwise.
// Ref: TS 33.501 §6.1.3.2 step 11, TS 35.206 §3.5 (f5*), §3.4 (f1*)
func ResyncFromAUTS(k, opc, rand [16]byte, auts [14]byte) ([6]byte, error) {
	akStar, err := milenage.F5Star(k, opc, rand)
	if err != nil {
		return [6]byte{}, fmt.Errorf("aka: resync: f5*: %w", err)
	}
	sqnMS := milenage.SQNFromAUTS(auts, akStar)
	var amfZero [2]byte
	macS := [8]byte(auts[6:14])
	ok, err := milenage.VerifyMACS(k, opc, rand, sqnMS, amfZero, macS)
	if err != nil {
		return [6]byte{}, fmt.Errorf("aka: resync: verify MAC-S: %w", err)
	}
	if !ok {
		return [6]byte{}, errors.New("aka: resync: MAC-S verification failed — AUTS rejected")
	}
	return sqnMS, nil
}

// IncrementSQN adds 1 to a 6-byte sequence number (big-endian 48-bit counter).
func IncrementSQN(sqn [6]byte) [6]byte {
	b := sqn
	for i := 5; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return b
}
