-- PDU Session ID per persisted session (TS 23.501 §5.6.1): lets a restarted SMF
-- ask the AMF to release the sessions it lost (TS 23.527 §4.3 restoration).
ALTER TABLE smf_sessions ADD COLUMN IF NOT EXISTS pdu_session_id INT NOT NULL DEFAULT 0;
