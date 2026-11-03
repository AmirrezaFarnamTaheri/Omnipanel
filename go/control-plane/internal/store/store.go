package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps pgxpool and provides typed access to all OmniPanel tables.
// Queries are executed directly with pgx (no codegen), so the store compiles
// without the sqlc toolchain.
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

// ---------- helpers ----------

func scanNode(row pgx.Row) (*Node, error) {
	var n Node
	var components []byte
	var keyHash sql.NullString
	var lastSeen sql.NullTime
	var agentVersion sql.NullString
	var appliedEpoch sql.NullInt32
	var appliedState sql.NullString
	err := row.Scan(
		&n.ID, &n.Name, &n.PublicAddress, &n.Provider, &n.ASN, &n.Region, &n.Status,
		&keyHash, &lastSeen, &agentVersion, &n.StructuralSeq, &n.MembershipSeq,
		&appliedEpoch, &n.AppliedStructuralSeq, &n.AppliedMembershipSeq, &appliedState,
		&components, &n.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	n.NodeKeyHash = keyHash.String
	n.LastSeenAt = lastSeen.Time
	n.AgentVersion = agentVersion.String
	if appliedEpoch.Valid {
		n.AppliedEpoch = &appliedEpoch.Int32
	}
	n.AppliedState = appliedState.String
	if err := json.Unmarshal(components, &n.Components); err != nil {
		n.Components = nil
	}
	return &n, nil
}

func scanInbound(row pgx.Row) (*Inbound, error) {
	var i Inbound
	var params []byte
	var secrets []byte
	err := row.Scan(
		&i.ID, &i.NodeID, &i.Name, &i.Runtime, &i.Protocol, &i.Transport,
		&i.Port, &i.SNI, &params, &secrets, &i.Enabled, &i.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(params, &i.Params)
	_ = json.Unmarshal(secrets, &i.Secrets)
	return &i, nil
}

func scanPrincipal(row pgx.Row) (*EndpointPrincipal, error) {
	var p EndpointPrincipal
	var revoked sql.NullTime
	err := row.Scan(
		&p.ID, &p.UserID, &p.InboundID, &p.AttributionKey, &p.CredentialEnc,
		&p.State, &p.CreatedAt, &revoked,
	)
	if err != nil {
		return nil, err
	}
	p.RevokedAt = revoked.Time
	return &p, nil
}

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var email sql.NullString
	var suspendReason sql.NullString
	var expiresAt sql.NullTime
	err := row.Scan(
		&u.ID, &u.Name, &email, &u.PlanID, &u.Status, &suspendReason, &expiresAt,
		&u.Version, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	u.Email = email.String
	u.SuspendReason = suspendReason.String
	u.ExpiresAt = expiresAt.Time
	return &u, nil
}

func scanPlan(row pgx.Row) (*Plan, error) {
	var p Plan
	var quota sql.NullInt64
	err := row.Scan(&p.ID, &p.Name, &quota, &p.Enforcement, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	p.QuotaBytes = quota.Int64
	return &p, nil
}

// ---------- domain types ----------

type Node struct {
	ID                int32     `json:"id"`
	Name              string    `json:"name"`
	PublicAddress     string    `json:"public_address"`
	Provider          string    `json:"provider"`
	ASN               string    `json:"asn"`
	Region            string    `json:"region"`
	Status            string    `json:"status"`
	NodeKeyHash       string    `json:"node_key_hash,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	AgentVersion      string    `json:"agent_version,omitempty"`
	StructuralSeq     int32     `json:"structural_seq"`
	MembershipSeq     int32     `json:"membership_seq"`
	AppliedEpoch      *int32    `json:"applied_epoch,omitempty"`
	AppliedStructuralSeq int32   `json:"applied_structural_seq"`
	AppliedMembershipSeq int32  `json:"applied_membership_seq"`
	AppliedState      string    `json:"applied_state"`
	Components        []Component `json:"components,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

type Component struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
}

type Inbound struct {
	ID        int32              `json:"id"`
	NodeID    int32              `json:"node_id"`
	Name      string             `json:"name"`
	Runtime   string             `json:"runtime"`
	Protocol  string             `json:"protocol"`
	Transport string             `json:"transport"`
	Port      int32              `json:"port"`
	SNI       string             `json:"sni"`
	Params    map[string]string  `json:"params,omitempty"`
	Secrets   map[string]string  `json:"secrets,omitempty"`
	Enabled   bool               `json:"enabled"`
	CreatedAt time.Time          `json:"created_at"`
}

type EndpointPrincipal struct {
	ID              int32      `json:"id"`
	UserID          int32      `json:"user_id"`
	InboundID       int32      `json:"inbound_id"`
	AttributionKey  string     `json:"attribution_key"`
	CredentialEnc   string     `json:"credential_enc"`
	State           string     `json:"state"`
	CreatedAt       time.Time  `json:"created_at"`
	RevokedAt       time.Time  `json:"revoked_at,omitempty"`
}

type User struct {
	ID             int32      `json:"id"`
	Name           string     `json:"name"`
	Email          string     `json:"email,omitempty"`
	PlanID         int32      `json:"plan_id"`
	Status         string     `json:"status"`
	SuspendReason  string     `json:"suspend_reason,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at,omitempty"`
	Version        int32      `json:"version"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type Plan struct {
	ID           int32     `json:"id"`
	Name         string    `json:"name"`
	QuotaBytes   int64     `json:"quota_bytes,omitempty"`
	Enforcement  string    `json:"enforcement"`
	CreatedAt    time.Time `json:"created_at"`
}

type Admin struct {
	ID            int32      `json:"id"`
	Email         string     `json:"email"`
	PasswordHash  string     `json:"-"`
	Role          string     `json:"role"`
	TotpSecretEnc string     `json:"-"`
	TotpEnabled   bool       `json:"totp_enabled"`
	CreatedAt     time.Time  `json:"created_at"`
}

var _ = sql.NullString{}
var _ = time.Second
