// Command omnipanel-admin is a deliberately loopback-only TLS 1.3 adapter
// for two-person signed-state approvals. It is not a signer or node runtime.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/control/adminruntime"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/control/desiredapproval"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/control/desiredapproval/httpapi"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
	_ "github.com/lib/pq"
)

type splitApproval struct {
	proposer *desiredapproval.Service
	reviewer *desiredapproval.Service
}

func (s *splitApproval) Propose(ctx context.Context, in desiredapproval.ProposalRequest) (desiredapproval.ProposalReceipt, error) {
	return s.proposer.Propose(ctx, in)
}
func (s *splitApproval) Review(ctx context.Context, in desiredapproval.ReviewRequest) (desiredapproval.Reviewable, error) {
	return s.reviewer.Review(ctx, in)
}
func (s *splitApproval) Approve(ctx context.Context, in desiredapproval.ApprovalRequest) (desiredapproval.ApprovalReceipt, error) {
	return s.reviewer.Approve(ctx, in)
}

func makeVerifier(t adminruntime.Trust) manifest.Verifier {
	v := manifest.Verifier{
		AuthorizedEpoch:     t.AuthorizedEpoch,
		TrustedSigners:      make(map[string]ed25519.PublicKey, len(t.Signers)),
		AllowedCapabilities: make(map[string]bool, len(t.Capabilities)),
		QualifiedBuilds:     make(map[string]manifest.Build, len(t.Builds)),
		MaxClockSkew:        time.Duration(t.MaxClockSkewSeconds) * time.Second,
	}
	for id, public := range t.Signers {
		raw, _ := base64.RawURLEncoding.DecodeString(public) // Load prevalidates exact canonical 32-byte keys.
		v.TrustedSigners[id] = ed25519.PublicKey(raw)
	}
	for _, c := range t.Capabilities {
		v.AllowedCapabilities[c] = true
	}
	for id, b := range t.Builds {
		v.QualifiedBuilds[id] = manifest.Build{
			Driver: b.Driver, Version: b.Version, ArtifactDigest: b.ArtifactDigest,
			Capabilities: append([]string(nil), b.Capabilities...),
		}
	}
	return v
}

func openRole(ctx context.Context, uri string, username string) (*sql.DB, error) {
	db, err := sql.Open("postgres", uri)
	if err != nil {
		return nil, errors.New("cannot construct PostgreSQL role pool")
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(15 * time.Minute)
	check, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if err := db.PingContext(check); err != nil {
		db.Close()
		return nil, errors.New("PostgreSQL role connection or TLS verification failed")
	}
	if err := adminruntime.VerifyPostgresRole(check, db, username); err != nil {
		db.Close()
		return nil, errors.New("PostgreSQL runtime identity failed least-privilege guard")
	}
	return db, nil
}

func run(ctx context.Context, configPath string) error {
	if os.Geteuid() == 0 {
		return errors.New("administrator service must run as a dedicated unprivileged OS user")
	}
	cfg, err := adminruntime.Load(configPath)
	if err != nil {
		return err
	}
	pools := make(map[string]*sql.DB, 3)
	defer func() {
		for _, db := range pools {
			_ = db.Close()
		}
	}()
	for _, role := range []string{"session", "propose", "review"} {
		uri := cfg.DSNs[role]
		db, err := openRole(ctx, uri.String(), uri.User.Username())
		if err != nil {
			return fmt.Errorf("%s role startup blocked: %w", role, err)
		}
		pools[role] = db
	}
	verifier := makeVerifier(cfg.Trust)
	propose, err := desiredapproval.NewService(pools["propose"], verifier)
	if err != nil {
		return errors.New("trusted proposal service could not initialize")
	}
	review, err := desiredapproval.NewService(pools["review"], verifier)
	if err != nil {
		return errors.New("trusted reviewer service could not initialize")
	}
	sessions, err := httpapi.NewSQLSessionChecker(pools["session"])
	if err != nil {
		return errors.New("live session checker could not initialize")
	}
	h, err := httpapi.New(&splitApproval{proposer: propose, reviewer: review}, sessions, cfg.Config.Origin, cfg.CSRFKey, time.Now)
	if err != nil {
		return errors.New("TLS/origin/CSRF boundary could not initialize")
	}
	// httpapi.New clones the key. Drop the bootstrap copy promptly.
	for i := range cfg.CSRFKey {
		cfg.CSRFKey[i] = 0
	}
	s := &http.Server{
		Addr:              cfg.Config.Listen,
		Handler:           http.TimeoutHandler(h, 12*time.Second, `{"type":"about:blank","title":"Service Unavailable","status":503}`),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cfg.TLSCert}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       18 * time.Second,
		WriteTimeout:      18 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, release := context.WithTimeout(context.Background(), 10*time.Second)
			defer release()
			_ = s.Shutdown(shutdown)
		case <-stopWatcher:
			return
		}
	}()
	err = s.ListenAndServeTLS("", "") // certificate and private key already loaded from verified owner-only files.
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("TLS administrator listener failed: %w", err)
	}
	return nil
}

func main() {
	path := flag.String("config", "", "absolute path to owner-only administrator runtime JSON")
	flag.Parse()
	if *path == "" {
		log.Fatal("-config is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *path); err != nil {
		log.Fatal("administrator runtime refused startup: ", err)
	}
}
