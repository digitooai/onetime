// Package api implements the REST surface.
//
// Two shapes of client have to be served well. A browser posts JSON and reads
// JSON. A shell one-liner or an AI agent pipes a value in on stdin and wants a
// single line of output it can hand to a human — which is why several endpoints
// accept a raw body and negotiate a plain-text response.
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/httpx"
	"github.com/digitooai/onetime/internal/ratelimit"
	"github.com/digitooai/onetime/internal/secret"
)

// Server holds the API dependencies.
type Server struct {
	cfg     *config.Config
	svc     *secret.Service
	limiter *ratelimit.Limiter
	log     *slog.Logger
}

// New builds the API server.
func New(cfg *config.Config, svc *secret.Service, limiter *ratelimit.Limiter, log *slog.Logger) *Server {
	return &Server{cfg: cfg, svc: svc, limiter: limiter, log: log}
}

// Register mounts the API routes.
//
// The endpoints that consume a secret sit behind the anti-prefetch gate; the
// ones that only create or describe do not, so a browser extension or a proxy
// probing them can do no damage.
func (s *Server) Register(mux *http.ServeMux) {
	consuming := httpx.AntiPrefetch(s.cfg.BaseURL)

	mux.Handle("POST /api/v1/secret", http.HandlerFunc(s.handleCreateText))
	mux.Handle("POST /api/v1/secret/file", http.HandlerFunc(s.handleCreateFileMultipart))
	mux.Handle("PUT /api/v1/secret/file", http.HandlerFunc(s.handleCreateFileStream))
	mux.Handle("POST /api/v1/generate", http.HandlerFunc(s.handleGenerate))
	mux.Handle("POST /api/v1/peek", http.HandlerFunc(s.handlePeek))
	mux.Handle("POST /api/v1/reveal", consuming(http.HandlerFunc(s.handleReveal)))
	mux.Handle("GET /api/v1/download", consuming(http.HandlerFunc(s.handleDownload)))
	mux.Handle("POST /api/v1/receipt", http.HandlerFunc(s.handleReceipt))
	mux.Handle("POST /api/v1/receipt/burn", consuming(http.HandlerFunc(s.handleBurn)))
	mux.Handle("GET /api/v1/config", http.HandlerFunc(s.handleConfig))
}

// IsStreamingRoute reports whether a path transfers a whole file and should be
// exempt from the ordinary handler timeout: a 50 MB transfer over a phone
// connection legitimately takes minutes.
func IsStreamingRoute(path string) bool {
	return path == "/api/v1/secret/file" || path == "/api/v1/download"
}

func (s *Server) handleCreateText(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionCreateText) {
		return
	}
	var req secret.CreateTextRequest
	req.Source = "api"

	switch contentType(r) {
	case "application/json":
		var body createRequest
		if !decodeJSON(w, r, &body, s.cfg.MaxTextBytes+4096) {
			return
		}
		req.Text = []byte(body.Secret)
		req.TTLDays = body.TTLDays
		req.Passphrase = crypto.Passphrase(body.Passphrase)

	default:
		// The raw path. `producer | curl --data-binary @-` puts the value on
		// stdin, where it never reaches argv and so never reaches `ps` output
		// or a shell history file.
		body, err := readLimited(r.Body, s.cfg.MaxTextBytes)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		req.Text = body
		req.Passphrase = crypto.Passphrase(r.Header.Get("X-Onetime-Passphrase"))
		days, err := ttlFromHeaders(r)
		if err != nil {
			s.badRequest(w, r, err.Error())
			return
		}
		req.TTLDays = days
	}

	created, err := s.svc.CreateText(r.Context(), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeCreated(w, r, created, nil)
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionGenerate) {
		return
	}
	var body generateRequest
	switch contentType(r) {
	case "application/json":
		if !decodeJSON(w, r, &body, 8192) {
			return
		}
	default:
		// Form encoding, so `curl -d length=24 -d ttl=7d` works. Nothing secret
		// travels this way: the whole point is that the password is invented
		// server-side and never passes through the caller.
		if err := r.ParseForm(); err != nil {
			s.badRequest(w, r, "could not read the form body")
			return
		}
		body.Length = atoiOr(r.PostForm.Get("length"), 0)
		body.Alphabet = r.PostForm.Get("alphabet")
		body.ReturnValue = truthy(r.PostForm.Get("return")) || truthy(r.PostForm.Get("return_value"))
		if ttl := firstNonEmpty(r.PostForm.Get("ttl"), r.PostForm.Get("ttl_days")); ttl != "" {
			days, err := parseTTL(ttl)
			if err != nil {
				s.badRequest(w, r, err.Error())
				return
			}
			body.TTLDays = days
		}
	}

	gen, err := s.svc.Generate(r.Context(), secret.GenerateRequest{
		Length:      body.Length,
		Alphabet:    body.Alphabet,
		TTLDays:     body.TTLDays,
		Passphrase:  crypto.Passphrase(body.Passphrase),
		ReturnValue: body.ReturnValue,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var value *string
	if gen.Value != "" {
		value = &gen.Value
	}
	s.writeCreated(w, r, gen.Created, value)
}

func (s *Server) handlePeek(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionPeek) {
		return
	}
	var body keyRequest
	if !decodeJSON(w, r, &body, 4096) {
		return
	}
	info, err := s.svc.Peek(r.Context(), body.Key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	resp := peekResponse{
		Exists:        true,
		State:         info.State,
		Kind:          info.Kind,
		HasPassphrase: info.HasPassphrase,
		Size:          info.Size,
		ExpiresAt:     rfc3339(info.ExpiresAt),
	}
	if info.HasPassphrase {
		left := info.AttemptsLeft
		resp.AttemptsLeft = &left
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionReveal) {
		return
	}
	var body keyRequest
	if !decodeJSON(w, r, &body, 8192) {
		return
	}
	revealed, err := s.svc.Reveal(r.Context(), secret.RevealRequest{
		Key:        body.Key,
		Passphrase: crypto.Passphrase(body.Passphrase),
		Confirm:    body.Confirm,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}

	resp := revealResponse{
		Kind:       revealed.Kind,
		Filename:   revealed.Filename,
		Size:       revealed.Size,
		RevealedAt: rfc3339(revealed.RevealedAt),
	}
	if revealed.Kind == "file" {
		resp.DownloadURL = "/api/v1/download"
		resp.DownloadTicket = revealed.Ticket
		resp.TicketExpiresIn = int(revealed.TicketTTL.Seconds())
		// The cookie lets a browser start the download by navigating, without
		// buffering the whole file through JavaScript first.
		//
		// Secure is conditional so that a plain-HTTP local development instance
		// still works; everything that actually protects the ticket is not.
		// HttpOnly and SameSite=Strict are unconditional, the value is a
		// single-use ticket with a five-minute life, and the __Host- prefix
		// makes the browser itself refuse the cookie unless it arrived over
		// HTTPS from the origin root — so on any deployment whose BaseURL is
		// https (which production always is) the flag is enforced twice over.
		//nolint:gosec // G124: Secure is gated on an https BaseURL for local dev; the __Host- prefix enforces it in the browser regardless
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-onetime_dl",
			Value:    revealed.Ticket,
			Path:     "/api/v1/download",
			MaxAge:   int(revealed.TicketTTL.Seconds()),
			Secure:   strings.HasPrefix(s.cfg.BaseURL, "https://"),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	} else {
		resp.Value = string(revealed.Text)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionDownload) {
		return
	}
	ticket := r.Header.Get("X-Onetime-Ticket")
	if ticket == "" {
		if c, err := r.Cookie("__Host-onetime_dl"); err == nil {
			ticket = c.Value
		}
	}
	if ticket == "" {
		s.fail(w, r, secret.ErrTicketExpired)
		return
	}

	dl, err := s.svc.OpenDownload(r.Context(), ticket)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer func() { _ = dl.Body.Close() }()

	name := dl.Filename
	if name == "" {
		name = "download"
	}
	h := w.Header()
	// Always octet-stream, never the uploader's declared type: serving an
	// uploaded .html back with its own content type would be stored XSS.
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", contentDisposition(name))
	h.Set("Content-Length", strconv.FormatInt(dl.Size, 10))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Accept-Ranges", "none")

	written, err := io.Copy(w, dl.Body)
	completed := err == nil && written == dl.Size
	dl.Done(completed)
	if err != nil {
		s.log.Warn("download did not finish",
			"request_id", httpx.RequestIDFrom(r.Context()), "written", written, "size", dl.Size, "error", err)
	}
}

func (s *Server) handleReceipt(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionReceipt) {
		return
	}
	var body keyRequest
	if !decodeJSON(w, r, &body, 4096) {
		return
	}
	status, err := s.svc.ReceiptStatus(r.Context(), body.Key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newReceiptResponse(status))
}

func (s *Server) handleBurn(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionBurn) {
		return
	}
	var body keyRequest
	if !decodeJSON(w, r, &body, 4096) {
		return
	}
	if !body.Confirm {
		s.fail(w, r, secret.ErrConfirmationRequired)
		return
	}
	status, err := s.svc.Burn(r.Context(), body.Key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, newReceiptResponse(status))
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, configResponse{
		MaxFileBytes:  s.cfg.MaxFileBytes,
		MaxTextBytes:  s.cfg.MaxTextBytes,
		TTLMinDays:    s.cfg.TTLMinDays,
		TTLMaxDays:    s.cfg.TTLMaxDays,
		TTLDefaultDay: s.cfg.TTLDefaultDays,
		FilesEnabled:  s.cfg.EnableFiles,
		ReadOnly:      s.cfg.ReadOnly,
	})
}

func (s *Server) writeCreated(w http.ResponseWriter, r *http.Request, c *secret.Created, value *string) {
	h := w.Header()
	h.Set("X-Onetime-Expires-At", rfc3339(c.ExpiresAt))
	h.Set("X-Onetime-Receipt-Url", c.ReceiptURL)

	// A plain-text caller gets exactly the link and nothing else, so an agent
	// can hand the whole response straight to a human.
	if httpx.PrefersPlainText(r) {
		httpx.WritePlain(w, http.StatusCreated, c.SecretURL)
		return
	}
	resp := newCreatedResponse(c)
	resp.Value = value
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (s *Server) allow(w http.ResponseWriter, r *http.Request, action ratelimit.Action) bool {
	res, err := s.limiter.Check(r.Context(), r, action)
	if err != nil {
		s.log.Warn("rate limiter unavailable, allowing the request",
			"request_id", httpx.RequestIDFrom(r.Context()), "action", action, "error", err)
	}
	if !res.Allowed {
		httpx.WriteRateLimited(w, r, res.RetryAfter)
		return false
	}
	return true
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	p := problemFor(err)
	if p.Status >= 500 {
		s.log.Error("request failed",
			"request_id", httpx.RequestIDFrom(r.Context()), "route", r.Pattern, "error", err)
	}
	httpx.WriteProblem(w, r, p)
}

func (s *Server) badRequest(w http.ResponseWriter, r *http.Request, detail string) {
	httpx.WriteProblem(w, r, httpx.Problem{
		Status: http.StatusBadRequest, Code: httpx.CodeBadRequest,
		Title: "Bad request", Detail: detail,
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	if err := dec.Decode(dst); err != nil {
		httpx.WriteProblem(w, r, httpx.Problem{
			Status: http.StatusBadRequest, Code: httpx.CodeBadRequest,
			Title: "Malformed JSON body",
			// Never echo the body back: on these endpoints the body is the
			// secret.
			Detail: "The request body could not be parsed as JSON.",
		})
		return false
	}
	return true
}

func readLimited(body io.Reader, limit int64) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, secret.ErrTooLarge
	}
	return buf, nil
}

func ttlFromHeaders(r *http.Request) (int, error) {
	if v := r.Header.Get("X-Onetime-TTL-Days"); v != "" {
		return parseTTL(v)
	}
	if v := r.Header.Get("X-Onetime-TTL"); v != "" {
		return parseTTL(v)
	}
	if v := r.URL.Query().Get("ttl_days"); v != "" {
		return parseTTL(v)
	}
	if v := r.URL.Query().Get("ttl"); v != "" {
		return parseTTL(v)
	}
	return 0, nil
}

func contentType(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// contentDisposition builds a header that is safe for any filename, including
// one with non-ASCII characters.
func contentDisposition(name string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + urlEscape(name)
}

func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on", "value", "raw":
		return true
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
