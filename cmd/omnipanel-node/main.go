// Command omnipanel-node is an unprivileged, node-initiated mTLS desired-state
// poller that verifies signed intent and persists it in a protected SQLite
// journal. It deliberately does NOT apply a host configuration or advance
// the applied cursor: those steps require native supervision and ACK evidence.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/bootstrap"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/gateway"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/reconcile"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
)

func pollOnce(ctx context.Context, c bootstrap.Config) (reconcile.Report, error) {
	verifier, err := c.Verifier()
	if err != nil { return reconcile.Report{}, err }
	ca, err := bootstrap.ReadPrivatePEM(c.RootCAFile)
	if err != nil { return reconcile.Report{}, err }
	cert, err := bootstrap.ReadPrivatePEM(c.ClientCertFile)
	if err != nil { return reconcile.Report{}, err }
	key, err := bootstrap.ReadPrivatePEM(c.ClientKeyFile)
	if err != nil { return reconcile.Report{}, err }
	client, err := gateway.New(gateway.Config{
		Origin: c.GatewayOrigin, NodeID: c.NodeID, RootCAPEM: ca,
		ClientCertificatePEM: cert, ClientPrivateKeyPEM: key,
	})
	if err != nil { return reconcile.Report{}, fmt.Errorf("gateway trust verification failed: %w", err) }
	journal, err := state.Open(c.JournalPath, c.NodeID, c.ControlPlaneEpoch)
	if err != nil { return reconcile.Report{}, fmt.Errorf("node journal unavailable: %w", err) }
	defer journal.Close()
	processor, err := reconcile.New(journal, verifier)
	if err != nil { return reconcile.Report{}, err }
	return processor.PollOnce(ctx, client)
}

func run(ctx context.Context, c bootstrap.Config, once bool) error {
	if os.Geteuid() == 0 {
		return errors.New("node polling service must run as an unprivileged OS user")
	}
	if _, err := c.Verifier(); err != nil { return err }
	for {
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.Canceled) { return nil }
			return err
		}
		report, err := pollOnce(ctx, c)
		if err != nil {
			if once { return fmt.Errorf("node desired-state poll failed: %w", err) }
			log.Printf("desired-state poll denied: %v", err)
		} else {
			log.Printf("desired-state outcome=%s structural=%d membership=%d pending_native_apply=%t",
				report.Outcome, report.StructuralSequence, report.MembershipSequence,
				report.Outcome == reconcile.PendingApplication)
		}
		if once { return nil }
		timer := time.NewTimer(time.Duration(c.PollSeconds) * time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() { <-timer.C }
			return nil
		case <-timer.C:
		}
	}
}

func main() {
	configPath := flag.String("config", "", "absolute path to owner-private node bootstrap JSON")
	once := flag.Bool("once", false, "poll once; nonzero exit on failure")
	flag.Parse()
	if *configPath == "" || flag.NArg() != 0 {
		log.Fatal("--config is required and no positional arguments are accepted")
	}
	c, err := bootstrap.Load(*configPath)
	if err != nil { log.Fatalf("node bootstrap rejected: %v", err) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, c, *once); err != nil {
		log.Fatalf("node polling service refused to start or continue: %v", err)
	}
}
