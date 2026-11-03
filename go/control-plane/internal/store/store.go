package store

import (
	"context"
	"database/sql"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps pgxpool and provides typed access to all OmniPanel tables.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a Store from a PostgreSQL connection URL.
func New(databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, err
	}
	log.Printf("connected to database")
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Pool returns the underlying pgxpool.Pool for direct use (e.g. in transactions).
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// Tx executes a function within a database transaction.
func (s *Store) Tx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			log.Printf("rollback failed: %v", rbErr)
		}
		return err
	}
	return tx.Commit(ctx)
}

// Ensure DB is var so it can be swapped in tests.
var _ = sql.NullString{}
