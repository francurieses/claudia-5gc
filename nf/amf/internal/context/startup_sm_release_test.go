package context

// startup_sm_release_test.go — unit tests for the SM context release performed
// at AMF startup (LoadFromStore), before the previous run's UE contexts are
// purged from PostgreSQL.
//
// The leak this closes: LoadFromStore deliberately purges every persisted UE
// context (after a restart all gNB SCTP associations are gone, so the contexts
// are stale). Those rows were the AMF's only record of which PDU sessions
// existed, so purging them without telling the SMF orphaned an SMF session, a
// UPF PFCP session and a UE IP per PDU session — permanently, on every restart.
//
// Ref: TS 23.007 §16, TS 29.502 §5.2.2.3.3.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/store"
)

// fakeStore is an in-memory store.Store recording the calls LoadFromStore makes.
type fakeStore struct {
	records  []*store.UERecord
	listErr  error
	purged   bool
	listedAt int // call order marker: value of callSeq when ListAllUEContexts ran
	purgedAt int
	callSeq  int
}

func (f *fakeStore) UpsertUE(context.Context, *store.UERecord) error { return nil }
func (f *fakeStore) GetUEBySUPI(context.Context, string) (*store.UERecord, error) {
	return nil, nil
}
func (f *fakeStore) GetUEByTMSI(context.Context, uint32) (*store.UERecord, error) {
	return nil, nil
}
func (f *fakeStore) DeleteUE(context.Context, string) error { return nil }
func (f *fakeStore) ListRegisteredUEs(context.Context) ([]*store.UERecord, error) {
	return f.records, nil
}
func (f *fakeStore) ListAllUEContexts(context.Context) ([]*store.UERecord, error) {
	f.callSeq++
	f.listedAt = f.callSeq
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.records, nil
}
func (f *fakeStore) MaxTMSI(context.Context) (uint32, error) { return 0, nil }
func (f *fakeStore) PurgeAllUEContexts(context.Context) (int64, error) {
	f.callSeq++
	f.purgedAt = f.callSeq
	f.purged = true
	return int64(len(f.records)), nil
}
func (f *fakeStore) Close() {}

// releaseRecorder records the smContextRefs handed to the releaser.
type releaseRecorder struct {
	mu   sync.Mutex
	refs []string
	err  error
}

func (r *releaseRecorder) release(_ context.Context, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refs = append(r.refs, ref)
	return r.err
}

func (r *releaseRecorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.refs...)
}

func newTestManager(db store.Store) *Manager {
	return NewManager(AMFIdentity{MCC: "001", MNC: "01"}, db, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func twoUEsWithSessions() []*store.UERecord {
	return []*store.UERecord{
		{
			SUPI: "imsi-001010000000001",
			PDUSessions: []store.PDUSessionRecord{
				{PDUSessionID: 1, SMFInstanceID: "ref-1", DNN: "internet"},
				{PDUSessionID: 2, SMFInstanceID: "ref-2", DNN: "ims"},
			},
		},
		{
			SUPI: "imsi-001010000000002",
			PDUSessions: []store.PDUSessionRecord{
				{PDUSessionID: 1, SMFInstanceID: "ref-3", DNN: "internet"},
			},
		},
	}
}

// TestLoadFromStore_ReleasesSMContextsBeforePurge is the core regression: every
// persisted PDU session must be released at the SMF, and it must happen BEFORE
// the purge — afterwards the refs are gone forever.
func TestLoadFromStore_ReleasesSMContextsBeforePurge(t *testing.T) {
	db := &fakeStore{records: twoUEsWithSessions()}
	rec := &releaseRecorder{}
	m := newTestManager(db)
	m.SetSMContextReleaser(rec.release)

	if err := m.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}

	got := rec.got()
	want := map[string]bool{"ref-1": true, "ref-2": true, "ref-3": true}
	if len(got) != len(want) {
		t.Fatalf("released %v, want the 3 refs %v", got, want)
	}
	for _, r := range got {
		if !want[r] {
			t.Errorf("released unexpected ref %q", r)
		}
	}
	if !db.purged {
		t.Error("contexts were not purged")
	}
	if db.listedAt == 0 || db.purgedAt == 0 || db.listedAt > db.purgedAt {
		t.Errorf("release ran after the purge (listed=%d purged=%d) — refs are gone by then",
			db.listedAt, db.purgedAt)
	}
}

// TestLoadFromStore_ReleaseFailureStillPurges asserts the release is
// best-effort: a booting/unreachable SMF must not stop the AMF from starting.
func TestLoadFromStore_ReleaseFailureStillPurges(t *testing.T) {
	db := &fakeStore{records: twoUEsWithSessions()}
	rec := &releaseRecorder{err: errors.New("smf unreachable")}
	m := newTestManager(db)
	m.SetSMContextReleaser(rec.release)

	if err := m.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("LoadFromStore must not fail when the SMF is unreachable: %v", err)
	}
	if len(rec.got()) != 3 {
		t.Errorf("attempted %d releases, want all 3 tried despite errors", len(rec.got()))
	}
	if !db.purged {
		t.Error("purge skipped after release failure — startup would keep stale rows")
	}
}

// TestLoadFromStore_ListFailureStillPurges: if the contexts cannot be listed we
// lose the refs, but startup must still proceed.
func TestLoadFromStore_ListFailureStillPurges(t *testing.T) {
	db := &fakeStore{records: twoUEsWithSessions(), listErr: errors.New("db down")}
	rec := &releaseRecorder{}
	m := newTestManager(db)
	m.SetSMContextReleaser(rec.release)

	if err := m.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}
	if len(rec.got()) != 0 {
		t.Errorf("released %v despite the list failing", rec.got())
	}
	if !db.purged {
		t.Error("purge skipped after list failure")
	}
}

// TestLoadFromStore_NoReleaserIsNoOp covers dev/test wiring with no SMF client.
func TestLoadFromStore_NoReleaserIsNoOp(t *testing.T) {
	db := &fakeStore{records: twoUEsWithSessions()}
	m := newTestManager(db) // no SetSMContextReleaser

	if err := m.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}
	if !db.purged {
		t.Error("purge skipped when no releaser is wired")
	}
}

// TestLoadFromStore_SkipsSessionsWithoutRef guards against DELETEing an empty
// smContextRef (a session that never reached the SMF).
func TestLoadFromStore_SkipsSessionsWithoutRef(t *testing.T) {
	db := &fakeStore{records: []*store.UERecord{{
		SUPI: "imsi-001010000000001",
		PDUSessions: []store.PDUSessionRecord{
			{PDUSessionID: 1, SMFInstanceID: ""},
			{PDUSessionID: 2, SMFInstanceID: "ref-real"},
		},
	}}}
	rec := &releaseRecorder{}
	m := newTestManager(db)
	m.SetSMContextReleaser(rec.release)

	if err := m.LoadFromStore(context.Background()); err != nil {
		t.Fatalf("LoadFromStore: %v", err)
	}
	got := rec.got()
	if len(got) != 1 || got[0] != "ref-real" {
		t.Errorf("released %v, want only [ref-real]", got)
	}
}
