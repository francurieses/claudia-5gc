package dbmigrate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

// fakeDB is an in-memory ledger; a failed fn discards its changes.
type fakeDB struct {
	ledger map[string]string
	execs  []string
	failOn string
}

func newFake() *fakeDB { return &fakeDB{ledger: map[string]string{}} }

type fakeTx struct {
	d      *fakeDB
	ledger map[string]string
	execs  []string
}

func (d *fakeDB) InTx(_ context.Context, fn func(Tx) error) error {
	t := &fakeTx{d: d, ledger: map[string]string{}}
	for k, v := range d.ledger {
		t.ledger[k] = v
	}
	if err := fn(t); err != nil {
		return err
	}
	d.ledger = t.ledger
	d.execs = append(d.execs, t.execs...)
	return nil
}

func (t *fakeTx) Exec(_ context.Context, sql string, args ...any) error {
	if t.d.failOn != "" && strings.Contains(sql, t.d.failOn) {
		return errors.New("boom")
	}
	if strings.HasPrefix(sql, "INSERT INTO schema_migrations") {
		t.ledger[args[0].(string)] = args[1].(string)
		return nil
	}
	t.execs = append(t.execs, sql)
	return nil
}

func (t *fakeTx) QueryString(_ context.Context, _ string, args ...any) (string, bool, error) {
	v, ok := t.ledger[args[0].(string)]
	return v, ok, nil
}

func fsys(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for k, v := range files {
		m["migrations/"+k] = &fstest.MapFile{Data: []byte(v)}
	}
	return m
}

func userExecs(d *fakeDB) []string {
	var out []string
	for _, e := range d.execs {
		if strings.HasPrefix(e, "CREATE TABLE IF NOT EXISTS t") || strings.HasPrefix(e, "ALTER") {
			out = append(out, e)
		}
	}
	return out
}

func TestRunRecordsAndIsIdempotent(t *testing.T) {
	d := newFake()
	fs := fsys(map[string]string{
		"002_b.sql": "ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT",
		"001_a.sql": "CREATE TABLE IF NOT EXISTS t (id INT)",
	})
	for i := 0; i < 2; i++ {
		if err := Run(context.Background(), d, "amf", fs, "migrations", nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.ledger) != 2 || d.ledger["amf/001_a.sql"] == "" {
		t.Fatalf("ledger = %v", d.ledger)
	}
	ex := userExecs(d)
	if len(ex) != 2 || !strings.HasPrefix(ex[0], "CREATE") {
		t.Fatalf("applied out of order or twice: %v", ex)
	}
}

func TestRunNamespacesIsolated(t *testing.T) {
	d := newFake()
	fs := fsys(map[string]string{"001_initial.sql": "CREATE TABLE IF NOT EXISTS t (id INT)"})
	for _, ns := range []string{"amf", "smf"} {
		if err := Run(context.Background(), d, ns, fs, "migrations", nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.ledger) != 2 {
		t.Fatalf("ledger = %v", d.ledger)
	}
}

func TestRunChecksumMismatch(t *testing.T) {
	d := newFake()
	_ = Run(context.Background(), d, "amf", fsys(map[string]string{"001.sql": "CREATE TABLE IF NOT EXISTS t (id INT)"}), "migrations", nil)
	err := Run(context.Background(), d, "amf", fsys(map[string]string{"001.sql": "CREATE TABLE IF NOT EXISTS t (id BIGINT)"}), "migrations", nil)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunRejectsDestructive(t *testing.T) {
	for _, sql := range []string{
		"DROP TABLE t", "truncate t", "ALTER TABLE t DROP COLUMN c",
		"ALTER TABLE t RENAME TO u", "DELETE FROM t", "ALTER TABLE t RENAME COLUMN a TO b",
	} {
		d := newFake()
		err := Run(context.Background(), d, "amf", fsys(map[string]string{"001.sql": sql}), "migrations", nil)
		if !errors.Is(err, ErrDestructive) {
			t.Errorf("%q: err = %v", sql, err)
		}
		if len(d.execs) != 0 {
			t.Errorf("%q: executed before lint", sql)
		}
	}
}

func TestLintIgnoresCommentsAndAdditive(t *testing.T) {
	sql := "-- never DROP TABLE here\nALTER TABLE t ADD COLUMN IF NOT EXISTS c INT; -- delete from later\n"
	if err := Lint("x", sql); err != nil {
		t.Fatal(err)
	}
}

func TestRunApplyFailureRollsBack(t *testing.T) {
	d := newFake()
	d.failOn = "BAD"
	fs := fsys(map[string]string{
		"001.sql": "CREATE TABLE IF NOT EXISTS t (id INT)",
		"002.sql": "CREATE TABLE IF NOT EXISTS BAD (id INT)",
	})
	err := Run(context.Background(), d, "amf", fs, "migrations", nil)
	if err == nil || !strings.Contains(err.Error(), "amf/002.sql") {
		t.Fatalf("err = %v", err)
	}
	if len(d.ledger) != 0 {
		t.Fatalf("ledger not rolled back: %v", d.ledger)
	}
}

func TestRunMissingDir(t *testing.T) {
	if err := Run(context.Background(), newFake(), "amf", fstest.MapFS{}, "migrations", nil); err == nil {
		t.Fatal("want error")
	}
}
