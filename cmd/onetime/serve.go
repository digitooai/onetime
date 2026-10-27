package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/digitooai/onetime/internal/api"
	"github.com/digitooai/onetime/internal/blob"
	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/httpx"
	"github.com/digitooai/onetime/internal/observability"
	"github.com/digitooai/onetime/internal/ratelimit"
	"github.com/digitooai/onetime/internal/secret"
	"github.com/digitooai/onetime/internal/store"
	"github.com/digitooai/onetime/internal/web"
)

// app is everything the server needs, assembled once at startup.
type app struct {
	cfg     *config.Config
	log     *slog.Logger
	store   *store.Redis
	blobs   *blob.Store
	svc     *secret.Service
	limiter *ratelimit.Limiter
	metrics *observability.Metrics
	health  *observability.Health
	reg     *prometheus.Registry
	started atomic.Bool
}

func runServe(ctx context.Context) error {
	a, err := setup(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = a.store.Close() }()

	collector := blob.NewCollector(a.blobs, a.store, a.log, a.cfg.OrphanGrace)
	collector.OnStats(func(s blob.Stats) {
		a.metrics.ReaperRuns.WithLabelValues("ok").Inc()
		a.metrics.ReaperOrphans.Add(float64(s.Orphans))
		a.metrics.ReaperReclaimed.Add(float64(s.BytesFreed))
		if s.TotalBlobs > 0 || s.TotalBytes > 0 {
			a.metrics.StorageBytes.Set(float64(s.TotalBytes))
			a.metrics.StorageFiles.Set(float64(s.TotalBlobs))
		}
		a.started.Store(true)
	})

	gcCtx, stopGC := context.WithCancel(context.Background())
	defer stopGC()
	if a.cfg.EnableFiles {
		go collector.Run(gcCtx, a.cfg.GCInterval, a.cfg.ReconcileInterval)
	} else {
		a.started.Store(true)
	}
	go a.watchRedis(gcCtx)

	appSrv := &http.Server{
		Addr:    a.cfg.ListenAddr,
		Handler: a.router(),
		// Generous, because a 50 MB upload from a phone is a legitimate slow
		// request. The per-handler timeout middleware covers the fast routes.
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          nil,
	}
	metricsSrv := &http.Server{
		Addr:              a.cfg.MetricsAddr,
		Handler:           a.metricsRouter(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 2)
	go func() {
		a.log.Info("listening", "addr", a.cfg.ListenAddr, "base_url", a.cfg.BaseURL, "version", version)
		if err := appSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("http server: %w", err)
		}
	}()
	go func() {
		a.log.Info("metrics listening", "addr", a.cfg.MetricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		a.log.Info("shutting down", "grace", a.cfg.ShutdownTimeout)
	}

	// Give in-flight transfers a chance to finish before the process exits;
	// cutting a download at 49 of 50 MB destroys a secret nobody received.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.cfg.ShutdownTimeout)
	defer cancel()
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		a.log.Warn("metrics server shutdown did not complete cleanly", "error", err)
	}
	if err := appSrv.Shutdown(shutdownCtx); err != nil {
		a.log.Warn("shutdown did not complete cleanly", "error", err)
	}
	stopGC()
	a.log.Info("stopped")
	return nil
}

func setup(ctx context.Context) (*app, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	log := observability.NewLogger(os.Stdout, cfg.LogLevel, cfg.LogFormat)

	if validateErr := cfg.Validate(); validateErr != nil {
		return nil, validateErr
	}

	keys, err := cfg.MasterKeys()
	if err != nil {
		return nil, err
	}
	ring, err := crypto.ParseKeyring(keys)
	if err != nil {
		return nil, err
	}
	deriver := crypto.NewDeriver(ring, crypto.KDFParams{
		MemKiB: cfg.Argon2MemKiB, Time: cfg.Argon2Time, Par: cfg.Argon2Par,
	}, cfg.Argon2Concurrency)

	password := ""
	if cfg.RedisPasswordFile != "" {
		raw, readErr := os.ReadFile(cfg.RedisPasswordFile)
		if readErr != nil {
			return nil, fmt.Errorf("read redis password: %w", readErr)
		}
		password = strings.TrimSpace(string(raw))
	}
	st, err := store.New(store.Options{
		Mode: cfg.RedisMode, Addr: cfg.RedisAddr, URL: cfg.RedisURL,
		Password: password, DB: cfg.RedisDB,
	})
	if err != nil {
		return nil, err
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if pingErr := waitForRedis(pingCtx, st, log); pingErr != nil {
		return nil, fmt.Errorf("redis is unreachable at startup: %w", pingErr)
	}
	if policyErr := st.CheckEvictionPolicy(pingCtx); policyErr != nil {
		if cfg.StrictStartup {
			return nil, policyErr
		}
		log.Error("redis eviction policy check failed", "error", policyErr)
	}
	// A master key that changed without the old one still in the ring means
	// every live secret just became permanently unreadable. That is worth
	// saying loudly at startup rather than discovering from a support ticket.
	if prev, mismatch, keyErr := st.CheckActiveKeyID(pingCtx, ring.ActiveID(), ring.IDs()); keyErr != nil {
		log.Warn("could not verify the master key id", "error", keyErr)
	} else if mismatch {
		log.Error("the previously active master key is missing from the keyring; "+
			"every secret written under it is now unreadable",
			"previous_key_id", prev, "active_key_id", ring.ActiveID())
	}

	blobs, err := blob.New(cfg.DataDir, cfg.TmpDir)
	if err != nil {
		return nil, err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := observability.NewMetrics(reg)
	metrics.SetBuildInfo(version, commit, runtime.Version())

	svc := secret.New(cfg, st, blobs, deriver, log)
	svc.SetEvents(secret.Events{
		Created: func(kind, source string, size int64) {
			metrics.SecretsCreated.WithLabelValues(kind, source).Inc()
			metrics.PayloadBytes.WithLabelValues(kind).Observe(float64(size))
			if kind == "file" {
				metrics.UploadBytes.Add(float64(size))
			}
		},
		Revealed: func(kind, result string) {
			metrics.SecretsRevealed.WithLabelValues(orUnknown(kind), result).Inc()
			metrics.LookupTotal.WithLabelValues(lookupResult(result)).Inc()
			if result == "unknown_key_id" {
				metrics.DecryptFailures.WithLabelValues("unknown_key_id").Inc()
			}
		},
		Burned: func(by string) {
			metrics.SecretsDestroyed.WithLabelValues(by).Inc()
		},
		PassFail: func() {
			metrics.PassphraseFails.Inc()
			metrics.LookupTotal.WithLabelValues("bad_key").Inc()
		},
	})

	limiter := ratelimit.New(st, cfg.TrustedProxies, nil, ratelimitPepper(ring), cfg.RateLimitEnabled)
	applyRateLimitOverrides(cfg, limiter, log)

	health := observability.NewHealth()
	health.Register("redis", func(ctx context.Context) error { return st.Ping(ctx) })
	if cfg.EnableFiles {
		health.Register("storage", func(context.Context) error {
			space, err := blobs.Space()
			if err != nil {
				return err
			}
			metrics.PVCFreeBytes.Set(float64(space.FreeBytes))
			metrics.DiskUsageRatio.Set(space.UsedRatio())
			if space.UsedRatio()*100 >= 98 {
				return fmt.Errorf("volume is %.0f%% full", space.UsedRatio()*100)
			}
			return nil
		})
	}

	a := &app{
		cfg: cfg, log: log, store: st, blobs: blobs, svc: svc,
		limiter: limiter, metrics: metrics, health: health, reg: reg,
	}
	health.SetStarted(a.started.Load)
	return a, nil
}

func (a *app) router() http.Handler {
	mux := http.NewServeMux()

	apiSrv := api.New(a.cfg, a.svc, a.limiter, a.log)
	apiSrv.Register(mux)

	web.Version = version
	webSrv, err := web.New(a.cfg, a.log)
	if err != nil {
		a.log.Error("could not prepare the web UI; serving the API only", "error", err)
	} else {
		webSrv.Register(mux)
	}

	mux.HandleFunc("GET /healthz", a.health.Live)
	mux.HandleFunc("GET /readyz", a.health.Ready)
	mux.HandleFunc("GET /startupz", a.health.Started)
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"version": version, "commit": commit, "buildDate": buildDate, "go": runtime.Version(),
		})
	})

	return httpx.Chain(mux,
		httpx.RequestID,
		httpx.Recover(a.log),
		httpx.AccessLog(a.log, a.cfg.TrustedProxies, "truncated"),
		httpx.WarnOnIgnoredForwarding(a.log, a.cfg.TrustedProxies),
		httpx.SecurityHeaders(a.cfg.BaseURL),
		httpx.RejectSecretInQuery,
		a.observe,
		noStoreExceptAssets,
		httpx.Timeout(30*time.Second, func(r *http.Request) bool {
			return api.IsStreamingRoute(r.URL.Path)
		}),
	)
}

// observe records request metrics using the route template, never the path:
// a path here contains a record id, and a metric label containing one would
// both explode cardinality and write identifiers into a page we scrape.
func (a *app) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.metrics.HTTPInflight.Inc()
		defer a.metrics.HTTPInflight.Dec()

		start := time.Now()
		rec := &codeRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)

		route := r.Pattern
		if route == "" {
			route = "other"
		}
		a.metrics.HTTPRequests.WithLabelValues(r.Method, route, itoa(rec.code)).Inc()
		a.metrics.HTTPDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		if rec.code == http.StatusTooManyRequests {
			a.metrics.RateLimitHits.WithLabelValues(route, "ip").Inc()
		}
	})
}

func (a *app) metricsRouter() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(a.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /healthz", a.health.Live)
	return mux
}

// watchRedis keeps the availability gauge honest between readiness probes.
func (a *app) watchRedis(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := a.store.Ping(pingCtx)
			cancel()
			if err != nil {
				a.metrics.RedisUp.Set(0)
				continue
			}
			a.metrics.RedisUp.Set(1)

			// Keep the active-secret gauge honest. A sharp drop in it is the
			// clearest signal that Redis lost its data, which is the one
			// failure mode with no recovery.
			countCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			waiting, _, err := a.store.SecretCounts(countCtx)
			cancel()
			if err != nil {
				a.log.Warn("could not count stored secrets", "error", err)
				continue
			}
			a.metrics.SecretsActive.Set(float64(waiting))
		}
	}
}

// noStoreExceptAssets keeps every dynamic page out of caches while letting the
// content-addressed static files be cached hard.
func noStoreExceptAssets(next http.Handler) http.Handler {
	inner := httpx.NoStore(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// ratelimitPepper derives the identity HMAC key from the master key, so that
// hashed client identities are neither guessable nor portable between
// deployments, without introducing another secret to manage.
func ratelimitPepper(ring *crypto.Keyring) []byte {
	active := ring.Active()
	pepper := make([]byte, 0, len(active)+len("ratelimit"))
	pepper = append(pepper, active...)
	return append(pepper, "ratelimit"...)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func lookupResult(revealResult string) string {
	switch revealResult {
	case "ok":
		return "hit"
	case "not_found":
		return "not_found"
	case "already":
		return "gone"
	default:
		return revealResult
	}
}

type codeRecorder struct {
	http.ResponseWriter
	code  int
	wrote bool
}

func (c *codeRecorder) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.wrote = true
	c.code = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *codeRecorder) Write(p []byte) (int, error) {
	c.wrote = true
	return c.ResponseWriter.Write(p)
}

func (c *codeRecorder) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// applyRateLimitOverrides folds any per-action environment overrides into the
// limiter.
//
// A malformed value is logged and skipped rather than fatal: one mistyped
// limiter is not worth refusing to start over, and the built-in default is a
// safe thing to fall back to.
func applyRateLimitOverrides(cfg *config.Config, limiter *ratelimit.Limiter, log *slog.Logger) {
	overrides, problems := cfg.RateLimitOverrides()
	for _, err := range problems {
		log.Error("ignoring a malformed rate limit override", "error", err)
	}
	if len(overrides) == 0 {
		return
	}
	converted := make(map[string]ratelimit.Policy, len(overrides))
	for action, limit := range overrides {
		converted[action] = ratelimit.Policy{PerHour: limit.PerHour, Burst: limit.Burst}
	}
	for _, name := range limiter.ApplyOverrides(converted) {
		log.Error("ignoring a rate limit override for an unknown action", "action", name)
	}
	for action, policy := range overrides {
		log.Info("rate limit overridden", "action", action, "per_hour", policy.PerHour, "burst", policy.Burst)
	}
}

// waitForRedis blocks until Redis answers or the context runs out.
//
// Redis runs as a sidecar, and Kubernetes gives no ordering guarantee between
// containers in a pod: on a cold start the application frequently wins the race
// and finds nothing listening. Exiting there is technically correct — the pod
// restarts and the second attempt succeeds — but it turns every rollout into a
// CrashLoopBackOff whose exponential delay grows each time, for a condition
// that resolves itself in a second or two.
func waitForRedis(ctx context.Context, st *store.Redis, log *slog.Logger) error {
	const probe = 500 * time.Millisecond
	var lastErr error
	for attempt := 1; ; attempt++ {
		lastErr = st.Ping(ctx)
		if lastErr == nil {
			if attempt > 1 {
				log.Info("redis became reachable", "attempts", attempt)
			}
			return nil
		}
		if ctx.Err() != nil {
			return lastErr
		}
		if attempt == 1 {
			log.Info("waiting for redis", "error", lastErr)
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(probe):
		}
	}
}
