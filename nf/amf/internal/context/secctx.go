package context

// secctx.go - the 5G NAS security context in use versus the one a SECURITY MODE
// COMMAND is taking into use (TS 24.501 §5.4.2.5).

// BeginSecurityCtxChange records that a new 5G NAS security context (the one
// written into SecurityCtx by the authentication procedure) is being taken into
// use by a SECURITY MODE COMMAND. The context in use before it (when it was
// active and not itself an unconfirmed one) is kept so a SECURITY MODE REJECT or
// an aborted procedure can fall back to it. Call before overwriting SecurityCtx.
// Ref: TS 24.501 §5.4.2.5
func (u *UEContext) BeginSecurityCtxChange() {
	u.secCtxMu.Lock()
	defer u.secCtxMu.Unlock()
	if u.secCtxPending {
		return // an earlier unconfirmed context is already being replaced
	}
	u.secCtxPending = true
	if u.SecurityCtx.Active {
		prev := u.SecurityCtx
		u.prevSecurityCtx = &prev
	} else {
		u.prevSecurityCtx = nil
	}
}

// CommitSecurityCtxChange promotes the new context after a verified SECURITY MODE
// COMPLETE: the previous context is dropped. Ref: TS 24.501 §5.4.2.4
func (u *UEContext) CommitSecurityCtxChange() {
	u.secCtxMu.Lock()
	u.secCtxPending = false
	u.prevSecurityCtx = nil
	u.secCtxMu.Unlock()
}

// SecurityCtxChangePending reports whether a SECURITY MODE COMMAND is outstanding
// for a context not yet confirmed.
func (u *UEContext) SecurityCtxChangePending() bool {
	u.secCtxMu.Lock()
	defer u.secCtxMu.Unlock()
	return u.secCtxPending
}

// RollbackSecurityCtxChange drops only the new, unconfirmed context (SECURITY MODE
// REJECT, T3560 abort, superseding request) and re-applies the one in use before
// the procedure, if any. It reports whether a change was pending and whether a
// previous context was restored (false: no context was in use, SecurityCtx is
// zeroed). Ref: TS 24.501 §5.4.2.5
func (u *UEContext) RollbackSecurityCtxChange() (pending, restored bool) {
	u.secCtxMu.Lock()
	defer u.secCtxMu.Unlock()
	if !u.secCtxPending {
		return false, false
	}
	u.secCtxPending = false
	if u.prevSecurityCtx != nil {
		u.SecurityCtx = *u.prevSecurityCtx
		u.prevSecurityCtx = nil
		return true, true
	}
	u.SecurityCtx = SecurityContext{}
	return true, false
}

// PreviousSecurityCtx returns a copy of the context in use before the pending
// SECURITY MODE COMMAND, or nil. Messages the UE protects with it (SECURITY MODE
// REJECT) are verified against it. Ref: TS 24.501 §5.4.2.5
func (u *UEContext) PreviousSecurityCtx() *SecurityContext {
	u.secCtxMu.Lock()
	defer u.secCtxMu.Unlock()
	if u.prevSecurityCtx == nil {
		return nil
	}
	c := *u.prevSecurityCtx
	return &c
}

// StorePreviousSecurityCtx writes back the previous context after it was used
// (its NAS COUNT advanced).
func (u *UEContext) StorePreviousSecurityCtx(c SecurityContext) {
	u.secCtxMu.Lock()
	if u.prevSecurityCtx != nil {
		u.prevSecurityCtx = &c
	}
	u.secCtxMu.Unlock()
}

// persistableSecurityCtx is the security context to persist: while a SECURITY
// MODE COMMAND is pending the new context is unconfirmed, so the previous
// (confirmed) one - or none - is stored, never the pending one.
// Ref: TS 24.501 §5.4.2.5
func (u *UEContext) persistableSecurityCtx() SecurityContext {
	u.secCtxMu.Lock()
	defer u.secCtxMu.Unlock()
	if !u.secCtxPending {
		return u.SecurityCtx
	}
	if u.prevSecurityCtx != nil {
		return *u.prevSecurityCtx
	}
	return SecurityContext{}
}

// MarkSecureExchange records that the secure exchange of NAS messages is
// established for the current N1 NAS signalling connection: an uplink message
// passed the integrity check with the current 5G NAS security context (a
// verified SECURITY MODE COMPLETE included). From then on every unprotected or
// integrity-failing message of this connection is discarded.
// Ref: TS 24.501 §4.4.4.3
func (u *UEContext) MarkSecureExchange() {
	u.secCtxMu.Lock()
	u.secureExchange = true
	u.secCtxMu.Unlock()
}

// ResetSecureExchange clears the flag when a new N1 NAS signalling connection
// starts (a new INITIAL UE MESSAGE for an existing context after CM-IDLE).
// Ref: TS 24.501 §4.4.4.3
func (u *UEContext) ResetSecureExchange() {
	u.secCtxMu.Lock()
	u.secureExchange = false
	u.secCtxMu.Unlock()
}

// SecureExchangeEstablished reports whether the secure exchange of NAS messages
// is established for the current N1 NAS signalling connection.
// Ref: TS 24.501 §4.4.4.3
func (u *UEContext) SecureExchangeEstablished() bool {
	u.secCtxMu.Lock()
	defer u.secCtxMu.Unlock()
	return u.secureExchange
}
