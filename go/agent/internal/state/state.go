package state

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database in WAL mode for agent local state.
type Store struct {
	db *sql.DB
}

// Open creates or opens the agent state database with WAL mode and required tables.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create state dir: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Enable WAL mode for concurrent read/write safety.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set wal mode: %w", err)
	}
	// Reasonable busy timeout for concurrent access.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}

	if err := createTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("create tables: %w", err)
	}

	log.Printf("agent state database opened: %s (WAL)", path)
	return &Store{db: db}, nil
}

// Close releases the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func createTables(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS agent_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		);`,
		`CREATE TABLE IF NOT EXISTS enrollment (
			node_id INTEGER NOT NULL,
			node_key TEXT NOT NULL,
			epoch INTEGER NOT NULL DEFAULT 0,
			enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (node_id)
		);`,
		`CREATE TABLE IF NOT EXISTS structural_cursor (
			node_id INTEGER NOT NULL PRIMARY KEY,
			sequence INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		);`,
		`CREATE TABLE IF NOT EXISTS membership_cursor (
			node_id INTEGER NOT NULL PRIMARY KEY,
			sequence INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT (datetime('now'))
		);`,
		`CREATE TABLE IF NOT EXISTS metering_buffer (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			attribution_key TEXT NOT NULL,
			generation TEXT NOT NULL,
			seq INTEGER NOT NULL,
			up INTEGER NOT NULL DEFAULT 0,
			down INTEGER NOT NULL DEFAULT 0,
			generation_start INTEGER NOT NULL DEFAULT 0,
			observed_at TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		);`,
		`CREATE INDEX IF NOT EXISTS idx_metering_buffer_attribution ON metering_buffer(attribution_key, generation);`,
	}
	for i, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("statement %d: %w", i, err)
		}
	}
	return nil
}

// Set stores a key/value pair in agent state.
func (s *Store) Set(key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO agent_state (key, value, updated_at) VALUES ($1, $2, datetime('on'))
		 ON CONFLICT(key) DO UPDATE SET value = $2, updated_at = datetime('now')`,
		key, value,
	)
	return err
}

// Get retrieves a value from agent state.
func (s *Store) Get(key string) (string, bool, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM agent_state WHERE key = $1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// Delete removes a key from agent state.
func (s *Store) Delete(key string) error {
	_, err := s.db.Exec(`DELETE FROM agent_state WHERE key = $1`, key)
	return err
}

// DB returns the underlying *sql.DB for direct use.
func (s *Store) DB() *sql.DB {
	return s.db
}
