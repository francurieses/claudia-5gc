// Package dbmigrate applies embedded SQL migrations to PostgreSQL and records
// them in a schema_migrations(version, checksum, applied_at) ledger.
//
// Rules (REL19-7.1, dev/rel19/PLAN.md Phase 7): expand/contract, additive only.
// Migrations must be idempotent (CREATE ... IF NOT EXISTS, ADD COLUMN IF NOT
// EXISTS) and must not contain destructive statements (DROP, TRUNCATE, RENAME,
// DELETE FROM, ALTER ... DROP): Run rejects such files before executing
// anything, so a rolling upgrade/downgrade within one release window can
// always read the previous schema.
//
// The ledger is shared by every NF that uses the same database, so versions are
// namespaced: "<namespace>/<file name>" (for example "amf/001_initial.sql").
// Files that were applied before the ledger existed are idempotent, so on the
// first run they are re-executed harmlessly and then recorded as applied.
package dbmigrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

// ledgerDDL creates the migration ledger.
const ledgerDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT        PRIMARY KEY,
    checksum   TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

// advisoryLockKey serialises concurrent NF start-ups that share the database
// (arbitrary constant: ASCII "dbmig").
const advisoryLockKey int64 = 0x64626d6967

// ErrChecksumMismatch is returned when an already-applied migration was edited.
var ErrChecksumMismatch = errors.New("dbmigrate: applied migration was modified")

// ErrDestructive is returned for a migration that breaks the additive-only rule.
var ErrDestructive = errors.New("dbmigrate: destructive statement in migration")

// Tx is the minimal transactional surface Run needs.
type Tx interface {
	// Exec runs a statement.
	Exec(ctx context.Context, sql string, args ...any) error
	// QueryString returns the single text column of the first row; ok is false when there is no row.
	QueryString(ctx context.Context, sql string, args ...any) (val string, ok bool, err error)
}

// DB runs fn inside one transaction (commit on nil, rollback on error).
type DB interface {
	InTx(ctx context.Context, fn func(Tx) error) error
}

var destructiveRe = regexp.MustCompile(
	`(?is)\b(drop\s+(table|column|index|schema|constraint|type|view)|truncate|rename\s+(to|column)|delete\s+from|alter\s+table\s+[^;]*\bdrop\b)`)

var commentRe = regexp.MustCompile(`(?m)--[^\n]*`)

// Lint reports ErrDestructive when sql contains a statement forbidden by the
// additive-only rule. SQL comments are ignored.
func Lint(name, sql string) error {
	if m := destructiveRe.FindString(commentRe.ReplaceAllString(sql, "")); m != "" {
		return fmt.Errorf("%w: %s: %q", ErrDestructive, name, m)
	}
	return nil
}

// Checksum returns the hex SHA-256 of a migration body.
func Checksum(sql []byte) string {
	h := sha256.Sum256(sql)
	return hex.EncodeToString(h[:])
}

// Run applies, in file-name order, every *.sql file of dir in fsys that is not
// yet in the ledger, under the given namespace. It is safe to call from several
// NFs and several times (idempotent). An applied file whose checksum changed
// yields ErrChecksumMismatch; a destructive file yields ErrDestructive. The
// whole run is one transaction. log may be nil.
func Run(ctx context.Context, db DB, namespace string, fsys fs.FS, dir string, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("dbmigrate: read %s: %w", dir, err)
	}
	type file struct{ version, sum, sql string }
	var files []file
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return fmt.Errorf("dbmigrate: read %s: %w", e.Name(), err)
		}
		if err := Lint(namespace+"/"+e.Name(), string(body)); err != nil {
			return err
		}
		files = append(files, file{namespace + "/" + e.Name(), Checksum(body), string(body)})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].version < files[j].version })

	err = db.InTx(ctx, func(tx Tx) error {
		if err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", advisoryLockKey); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		if err := tx.Exec(ctx, ledgerDDL); err != nil {
			return fmt.Errorf("create ledger: %w", err)
		}
		for _, f := range files {
			sum, ok, err := tx.QueryString(ctx, "SELECT checksum FROM schema_migrations WHERE version = $1", f.version)
			if err != nil {
				return fmt.Errorf("ledger lookup %s: %w", f.version, err)
			}
			if ok {
				if sum != f.sum {
					return fmt.Errorf("%w: %s (ledger %s, file %s)", ErrChecksumMismatch, f.version, sum, f.sum)
				}
				continue
			}
			if err := tx.Exec(ctx, f.sql); err != nil {
				return fmt.Errorf("apply %s: %w", f.version, err)
			}
			if err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)", f.version, f.sum); err != nil {
				return fmt.Errorf("record %s: %w", f.version, err)
			}
			log.Info("migration applied", "interface", "Postgres", "direction", "OUT",
				"procedure", "DbMigrate", "result", "OK", "version", f.version,
				"spec_ref", "REL19-7.1 expand/contract")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("dbmigrate: %s: %w", namespace, err)
	}
	return nil
}
