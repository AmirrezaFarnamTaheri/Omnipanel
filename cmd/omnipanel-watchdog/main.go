// Command omnipanel-watchdog is a separately supervised, non-root recovery
// process. It does not activate a candidate or acknowledge applied revisions.
// A separately reviewed root supervisor server is a mandatory deployment input.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/state"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/supervisoripc"
	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/watchdog"
)

var (
	errInvalidWatchdogOptions = errors.New("watchdog requires an authorized node/epoch, private journal, root supervisor socket and bounded interval")
	watchdogUUIDPattern       = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
)

type options struct {
	NodeID           string
	Epoch            string
	JournalPath      string
	SupervisorSocket string
	Interval         time.Duration
}

func privateAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func (o options) validate() error {
	if !watchdogUUIDPattern.MatchString(o.NodeID) || !watchdogUUIDPattern.MatchString(o.Epoch) ||
		!privateAbsolutePath(o.JournalPath) || !privateAbsolutePath(o.SupervisorSocket) ||
		o.Interval < 10*time.Millisecond || o.Interval > time.Second {
		return errInvalidWatchdogOptions
	}
	return nil
}

func run(ctx context.Context, cfg options) error {
	if ctx == nil {
		return errInvalidWatchdogOptions
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("watchdog must run as a dedicated unprivileged user")
	}
	// Fail closed before touching the SQLite journal unless an authenticated,
	// root-owned Unix supervisor is already provisioned and reachable.
	supervisor, err := supervisoripc.New(cfg.SupervisorSocket)
	if err != nil {
		return err
	}
	journal, err := state.Open(cfg.JournalPath, cfg.NodeID, cfg.Epoch)
	if err != nil {
		return err
	}
	defer journal.Close()
	var lastStatus watchdog.Result
	lastLog := time.Time{}
	monitor, err := watchdog.New(journal, supervisor, cfg.Interval, func(outcome watchdog.Result, failure error) {
		now := time.Now()
		if outcome != lastStatus || (failure != nil && now.Sub(lastLog) >= time.Minute) {
			// Never print raw IPC/SQLite errors or private config to service logs.
			log.Printf("watchdog state=%s recovery_error=%t", outcome, failure != nil)
			lastStatus, lastLog = outcome, now
		}
	})
	if err != nil {
		return err
	}
	return monitor.Run(ctx)
}

func main() {
	cfg := options{}
	flag.StringVar(&cfg.NodeID, "node-id", "", "locally authorized node UUID")
	flag.StringVar(&cfg.Epoch, "epoch", "", "locally authorized control-plane epoch UUID")
	flag.StringVar(&cfg.JournalPath, "journal", "", "absolute path to protected node SQLite WAL journal")
	flag.StringVar(&cfg.SupervisorSocket, "supervisor-socket", "", "absolute path to root-owned Unix rollback supervisor socket")
	flag.DurationVar(&cfg.Interval, "interval", 250*time.Millisecond, "independent recovery check interval (10ms to 1s)")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("watchdog accepts no positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("watchdog refused to run: %v", err)
	}
}
