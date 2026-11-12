package dbmigrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgxDB adapts a pgx pool to DB.
type PgxDB struct{ Pool *pgxpool.Pool }

type pgxTx struct{ tx pgx.Tx }

// InTx implements DB.
func (d PgxDB) InTx(ctx context.Context, fn func(Tx) error) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	if err := fn(pgxTx{tx}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (t pgxTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t pgxTx) QueryString(ctx context.Context, sql string, args ...any) (string, bool, error) {
	var v string
	err := t.tx.QueryRow(ctx, sql, args...).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}
