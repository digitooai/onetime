package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/digitooai/onetime/internal/blob"
	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/observability"
	"github.com/digitooai/onetime/internal/store"
)

// runHealthcheck probes the local server.
//
// It exists because the runtime image is distroless: there is no shell, no
// curl and no wget for a container HEALTHCHECK to use, so the binary probes
// itself.
func runHealthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	addr := cfg.ListenAddr
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("cannot read the listen address %q: %w", cfg.ListenAddr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"
	resp, err := client.Get(url) //nolint:noctx // short-lived probe with its own timeout
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain so the connection can be reused. The probe's verdict is the status
	// code alone, so a short read here changes nothing about the answer.
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining a probe body; its contents are never read

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s returned %d", url, resp.StatusCode)
	}
	return nil
}

// runKeygen prints a new keyring entry.
//
// Rotation is meant to be additive: put the new entry first and keep the old
// one after it, so records written under the old key stay readable until they
// expire. Replacing the ring outright makes every live secret unreadable.
func runKeygen() error {
	id := "v1"
	if len(os.Args) > 2 {
		id = os.Args[2]
	}
	entry, err := crypto.GenerateKeyringEntry(id)
	if err != nil {
		return err
	}
	fmt.Println(entry)
	fmt.Fprintln(os.Stderr,
		"\nPut this first in ONETIME_MASTER_KEYS and keep the previous entry after it:\n"+
			"  ONETIME_MASTER_KEYS=\""+entry+",<previous entry>\"\n"+
			"Drop the old entry only once every secret written under it has expired.")
	return nil
}

// runGC performs one collection pass and exits, for use from kubectl exec when
// the volume needs reclaiming sooner than the background loop would manage.
func runGC(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := observability.NewLogger(os.Stderr, cfg.LogLevel, "text")

	st, err := store.New(store.Options{
		Mode: cfg.RedisMode, Addr: cfg.RedisAddr, URL: cfg.RedisURL, DB: cfg.RedisDB,
	})
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	if pingErr := st.Ping(ctx); pingErr != nil {
		return fmt.Errorf("redis is unreachable: %w", pingErr)
	}

	blobs, err := blob.New(cfg.DataDir, cfg.TmpDir)
	if err != nil {
		return err
	}

	collector := blob.NewCollector(blobs, st, log, cfg.OrphanGrace)
	swept, err := collector.Sweep(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	reconciled, err := collector.Reconcile(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}

	fmt.Printf("swept:     %d deleted, %d bytes reclaimed\n", swept.Deleted, swept.BytesFreed)
	fmt.Printf("reconciled: %d deleted (%d orphans), %d bytes reclaimed\n",
		reconciled.Deleted, reconciled.Orphans, reconciled.BytesFreed)
	fmt.Printf("remaining:  %d files, %d bytes\n", reconciled.TotalBlobs, reconciled.TotalBytes)
	return nil
}
