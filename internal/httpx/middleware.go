package httpx

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/digitooai/onetime/internal/ratelimit"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxNonce
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware so that the first listed is the outermost.
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// RequestID attaches a correlation id to the context and the response.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := randomID()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

// RequestIDFrom reads the correlation id back out. It returns "" outside a
// request, which is what callers want: a log line without a correlation id is
// still worth emitting.
func RequestIDFrom(ctx context.Context) string {
	id, ok := ctx.Value(ctxRequestID).(string)
	if !ok {
		return ""
	}
	return id
}

// NonceFrom reads the per-response CSP nonce. An empty result means the
// template renders no nonce attribute, so the script is blocked by the policy
// rather than silently allowed.
func NonceFrom(ctx context.Context) string {
	n, ok := ctx.Value(ctxNonce).(string)
	if !ok {
		return ""
	}
	return n
}

// Recover turns a panic into a 500 without leaking anything about the request.
//
// The stack trace goes to the log; the request does not. A handler here holds
// plaintext secrets in local variables, and a panic dump that included the
// request body or headers would write them straight into the log stream this
// service promises never to do that with.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					// net/http uses this panic as a control signal to abandon a
					// response, not as a failure; re-panic so the server sees it.
					if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
						panic(rec)
					}
					log.Error("handler panicked",
						"request_id", RequestIDFrom(r.Context()),
						"route", routePattern(r),
						"panic", rec,
						"stack", string(debug.Stack()))
					WriteProblem(w, r, Problem{
						Status: http.StatusInternalServerError,
						Code:   CodeInternal,
						Title:  "Something broke on our side",
						Detail: "Please try again shortly.",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout bounds how long a handler may run. Upload and download handlers opt
// out, because a 50 MB transfer on a slow phone legitimately takes minutes.
func Timeout(d time.Duration, exempt func(*http.Request) bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exempt != nil && exempt(r) {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RejectSecretInQuery refuses any request that carries what looks like a secret
// in the URL.
//
// A query string is the one place a secret must never appear: it lands in proxy
// logs, browser history and referrer headers, and there is no taking it back.
// Rather than quietly accepting it, we fail loudly and tell the caller the
// value they just sent has to be treated as compromised.
func RejectSecretInQuery(next http.Handler) http.Handler {
	suspect := []string{"secret", "value", "password", "passphrase", "key", "token", "pass"}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			q := r.URL.Query()
			for _, name := range suspect {
				if v := q.Get(name); v != "" {
					WriteProblem(w, r, Problem{
						Status: http.StatusBadRequest,
						Code:   CodeSecretInQuery,
						Title:  "Secrets must not travel in the URL",
						Detail: "The value you just sent in the query string appeared in the URL and must be " +
							"considered compromised. Rotate it, then send it in the request body instead.",
						Example: "printf %s \"$VALUE\" | curl -sS --data-binary @- " +
							"-H 'Content-Type: text/plain' https://onetime.digitoo.ai/api/v1/secret",
					})
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// WarnOnIgnoredForwarding reports, at most once a minute, that forwarding
// headers are arriving from an untrusted peer.
//
// This exists because the misconfiguration it catches is otherwise invisible.
// If trustedProxies does not cover the ingress controller, the app keeps
// serving traffic normally but attributes every request to the controller's own
// address — so the daily upload quota and the passphrase throttle silently
// collapse into one bucket shared by everybody. Nothing fails; people just
// start getting throttled for someone else's activity.
func WarnOnIgnoredForwarding(log *slog.Logger, trusted []netip.Prefix) Middleware {
	var mu sync.Mutex
	var last time.Time
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ratelimit.ForwardedIgnored(r, trusted) {
				mu.Lock()
				if time.Since(last) > time.Minute {
					last = time.Now()
					mu.Unlock()
					log.Warn("ignoring X-Forwarded-For from an untrusted peer; "+
						"every client is being attributed to this address, so rate limits and quotas are shared by all users. "+
						"Set ONETIME_TRUSTED_PROXIES (Helm: config.trustedProxies) to the ingress controller's pod CIDR",
						"peer", maskIP(ratelimit.ClientIP(r, nil), "truncated"),
						"trusted_prefixes", len(trusted))
				} else {
					mu.Unlock()
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog records one line per request.
//
// It logs the route pattern rather than the path. That is not cosmetic: the
// path contains a record id, and on some routes the raw target is the one thing
// we have promised never to write down. Query strings are never logged at all.
func AccessLog(log *slog.Logger, trusted []netip.Prefix, ipMode string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			attrs := []any{
				"request_id", RequestIDFrom(r.Context()),
				"method", r.Method,
				"route", routePattern(r),
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"bytes_out", rec.written,
				"user_agent", truncate(r.UserAgent(), 120),
			}
			if ip := ratelimit.ClientIP(r, trusted); ip.IsValid() {
				attrs = append(attrs, "client_ip", maskIP(ip, ipMode))
			}
			switch {
			case rec.status >= 500:
				log.Error("request", attrs...)
			case rec.status >= 400:
				log.Warn("request", attrs...)
			default:
				log.Info("request", attrs...)
			}
		})
	}
}

// maskIP narrows a client address for logging. Truncating to a network is
// enough to spot abuse patterns without keeping a record of who used a service
// whose whole point is not keeping records.
func maskIP(addr netip.Addr, mode string) string {
	switch mode {
	case "full":
		return addr.String()
	case "none":
		return ""
	default:
		bits := 24
		if addr.Is6() && !addr.Is4In6() {
			bits = 48
		}
		if p, err := addr.Prefix(bits); err == nil {
			return p.String()
		}
		return ""
	}
}

// routePattern returns the matched route template, falling back to a redacted
// placeholder so a raw path can never reach the log by accident.
func routePattern(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	if i := strings.IndexByte(r.URL.Path, '?'); i >= 0 {
		return r.URL.Path[:i]
	}
	// Unmatched paths are still safe to log only after stripping anything that
	// could be an identifier.
	parts := strings.Split(r.URL.Path, "/")
	for i, p := range parts {
		if len(p) > 12 {
			parts[i] = "{redacted}"
		}
	}
	return strings.Join(parts, "/")
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wrote {
		return
	}
	s.wrote = true
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(p []byte) (int, error) {
	if !s.wrote {
		s.wrote = true
	}
	n, err := s.ResponseWriter.Write(p)
	s.written += int64(n)
	return n, err
}

// Flush forwards to the underlying writer so streaming downloads are not held
// in a buffer.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func randomID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
