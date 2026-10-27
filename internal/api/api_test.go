package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	redisclient "github.com/redis/go-redis/v9"

	"github.com/digitooai/onetime/internal/blob"
	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/httpx"
	"github.com/digitooai/onetime/internal/ratelimit"
	"github.com/digitooai/onetime/internal/secret"
	"github.com/digitooai/onetime/internal/store"
)

type testServer struct {
	mux *http.ServeMux
	log *lockedBuffer
	cfg *config.Config
}

// lockedBuffer collects log output from concurrent handlers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redisclient.NewClient(&redisclient.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	dir := t.TempDir()
	blobs, err := blob.New(dir+"/blobs", dir+"/tmp")
	if err != nil {
		t.Fatalf("blob.New: %v", err)
	}

	t.Setenv("ONETIME_MASTER_KEYS", "v1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, crypto.MasterKeyLen)))
	t.Setenv("ONETIME_BASE_URL", "https://onetime.example")
	t.Setenv("ONETIME_DATA_DIR", dir+"/blobs")
	t.Setenv("ONETIME_TMP_DIR", dir+"/tmp")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	keys, _ := cfg.MasterKeys()
	ring, _ := crypto.ParseKeyring(keys)
	deriver := crypto.NewDeriver(ring, crypto.KDFParams{MemKiB: 64, Time: 1, Par: 1}, 2)

	st := store.NewWithClient(client)
	limiter := ratelimit.New(st, nil, nil, []byte("test-pepper"), false)

	logBuf := &lockedBuffer{}
	log := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The service shares the captured logger so that TestNoSecretMaterialInLogs
	// covers the domain layer's log lines too, not just the HTTP layer's.
	svc := secret.New(cfg, st, blobs, deriver, log)

	mux := http.NewServeMux()
	New(cfg, svc, limiter, log).Register(mux)
	return &testServer{mux: mux, log: logBuf, cfg: cfg}
}

// do sends a request through the mux, applying the middleware that guards the
// real server so that tests exercise the same stack.
func (ts *testServer) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler := httpx.Chain(ts.mux, httpx.RequestID, httpx.RejectSecretInQuery)
	handler.ServeHTTP(w, r)
	return w
}

func (ts *testServer) postJSON(path string, body any, headers ...string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return ts.do(r)
}

// createText makes a secret and returns its fragment key and receipt key.
func (ts *testServer) createText(t *testing.T, text string, passphrase string) (string, string) {
	t.Helper()
	body := map[string]any{"secret": text}
	if passphrase != "" {
		body["passphrase"] = passphrase
	}
	w := ts.postJSON("/api/v1/secret", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", w.Code, w.Body.String())
	}
	var resp createdResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return fragmentOf(t, resp.SecretURL), fragmentOf(t, resp.ReceiptURL)
}

func fragmentOf(t *testing.T, url string) string {
	t.Helper()
	_, frag, ok := strings.Cut(url, "#")
	if !ok {
		t.Fatalf("link %q carries no fragment", url)
	}
	return frag
}

func TestCreateAndRevealOverHTTP(t *testing.T) {
	ts := newTestServer(t)
	key, _ := ts.createText(t, "hunter2", "")

	w := ts.postJSON("/api/v1/peek", map[string]any{"key": key})
	if w.Code != http.StatusOK {
		t.Fatalf("peek returned %d: %s", w.Code, w.Body.String())
	}

	w = ts.postJSON("/api/v1/reveal", map[string]any{"key": key, "confirm": true},
		"Sec-Fetch-Site", "same-origin", "Sec-Fetch-Mode", "cors", "Sec-Fetch-Dest", "empty")
	if w.Code != http.StatusOK {
		t.Fatalf("reveal returned %d: %s", w.Code, w.Body.String())
	}
	var resp revealResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Value != "hunter2" {
		t.Fatalf("revealed %q, want hunter2", resp.Value)
	}
}

// TestAntiPrefetchMatrix is the complete specification of who may consume a
// secret. It is a table rather than prose because the rules interact: a browser
// is held to same-origin scripted requests, a command-line client sends no
// Sec-Fetch headers at all and must still work, and anything announcing itself
// as speculative is answered without touching the record.
func TestAntiPrefetchMatrix(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		confirm bool
		want    int
		// consumes records whether a successful call should have burned it.
		consumes bool
	}{
		{
			name:     "command line client, no browser headers",
			headers:  map[string]string{"User-Agent": "curl/8.7.1"},
			confirm:  true,
			want:     http.StatusOK,
			consumes: true,
		},
		{
			name: "browser fetch from our own page",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
			},
			confirm:  true,
			want:     http.StatusOK,
			consumes: true,
		},
		{
			name: "browser navigating straight to the endpoint",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
			},
			confirm: true,
			want:    http.StatusForbidden,
		},
		{
			name: "cross-origin scripted request",
			headers: map[string]string{
				"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
			},
			confirm: true,
			want:    http.StatusForbidden,
		},
		{
			name:    "declared prefetch via Sec-Purpose",
			headers: map[string]string{"Sec-Purpose": "prefetch"},
			confirm: true,
			want:    http.StatusNoContent,
		},
		{
			name:    "declared prefetch via Purpose",
			headers: map[string]string{"Purpose": "prefetch"},
			confirm: true,
			want:    http.StatusNoContent,
		},
		{
			name:    "declared prefetch via X-Moz",
			headers: map[string]string{"X-Moz": "prefetch"},
			confirm: true,
			want:    http.StatusNoContent,
		},
		{
			name:    "declared preview via X-Purpose",
			headers: map[string]string{"X-Purpose": "preview"},
			confirm: true,
			want:    http.StatusNoContent,
		},
		{
			name:    "mismatched Origin",
			headers: map[string]string{"Origin": "https://evil.example"},
			confirm: true,
			want:    http.StatusForbidden,
		},
		{
			name:    "no confirmation",
			headers: map[string]string{"User-Agent": "curl/8.7.1"},
			confirm: false,
			want:    http.StatusBadRequest,
		},
		{
			// A preview bot's user agent is not itself a reason to refuse the
			// API: blocking by user agent would break the CLI clients this
			// service exists to serve, and the real defence is that a bot
			// never has the fragment key to send in the first place.
			name:     "preview bot user agent with a valid key still works",
			headers:  map[string]string{"User-Agent": "Slackbot-LinkExpanding 1.0"},
			confirm:  true,
			want:     http.StatusOK,
			consumes: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t)
			key, _ := ts.createText(t, "matrix", "")

			headers := make([]string, 0, len(tc.headers)*2)
			for k, v := range tc.headers {
				headers = append(headers, k, v)
			}
			body := map[string]any{"key": key}
			if tc.confirm {
				body["confirm"] = true
			}
			w := ts.postJSON("/api/v1/reveal", body, headers...)
			if w.Code != tc.want {
				t.Fatalf("reveal returned %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}

			// Whatever the outcome, the record must be in the state the case
			// implies: refusing a request that would have burned it is only
			// useful if the secret is genuinely still there afterwards.
			peek := ts.postJSON("/api/v1/peek", map[string]any{"key": key})
			if tc.consumes {
				if peek.Code == http.StatusOK {
					t.Fatal("secret survived a successful reveal")
				}
			} else if peek.Code != http.StatusOK {
				t.Fatalf("secret was consumed by a refused request (peek returned %d)", peek.Code)
			}
		})
	}
}

func TestPassphraseFlowOverHTTP(t *testing.T) {
	ts := newTestServer(t)
	key, _ := ts.createText(t, "protected", "correct horse")

	for _, tc := range []struct {
		name string
		body map[string]any
		want int
	}{
		{"no passphrase", map[string]any{"key": key, "confirm": true}, http.StatusUnauthorized},
		{"wrong passphrase", map[string]any{"key": key, "confirm": true, "passphrase": "nope"}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := ts.postJSON("/api/v1/reveal", tc.body)
			if w.Code != tc.want {
				t.Fatalf("returned %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}

	// After both failures the secret is still readable with the right answer.
	w := ts.postJSON("/api/v1/reveal", map[string]any{"key": key, "confirm": true, "passphrase": "correct horse"})
	if w.Code != http.StatusOK {
		t.Fatalf("correct passphrase returned %d: %s", w.Code, w.Body.String())
	}
}

func TestReceiptCanCancelButNotRead(t *testing.T) {
	ts := newTestServer(t)
	secretKey, receiptKey := ts.createText(t, "oops", "")

	w := ts.postJSON("/api/v1/receipt", map[string]any{"key": receiptKey})
	if w.Code != http.StatusOK {
		t.Fatalf("receipt returned %d: %s", w.Code, w.Body.String())
	}

	// The receipt key must not work as a secret key.
	if w := ts.postJSON("/api/v1/reveal", map[string]any{"key": receiptKey, "confirm": true}); w.Code != http.StatusNotFound {
		t.Fatalf("revealing with the receipt key returned %d, want 404", w.Code)
	}

	if w := ts.postJSON("/api/v1/receipt/burn", map[string]any{"key": receiptKey}); w.Code != http.StatusBadRequest {
		t.Fatalf("burn without confirmation returned %d, want 400", w.Code)
	}
	if w := ts.postJSON("/api/v1/receipt/burn", map[string]any{"key": receiptKey, "confirm": true}); w.Code != http.StatusOK {
		t.Fatalf("burn returned %d: %s", w.Code, w.Body.String())
	}
	if w := ts.postJSON("/api/v1/reveal", map[string]any{"key": secretKey, "confirm": true}); w.Code != http.StatusGone {
		t.Fatalf("reveal after burn returned %d, want 410", w.Code)
	}
}

func TestGenerateWithholdsValueByDefault(t *testing.T) {
	ts := newTestServer(t)

	w := ts.postJSON("/api/v1/generate", map[string]any{"length": 24})
	if w.Code != http.StatusCreated {
		t.Fatalf("generate returned %d: %s", w.Code, w.Body.String())
	}
	var resp createdResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Value != nil {
		t.Fatal("generate returned the password without being asked; an agent must not receive it by default")
	}

	w = ts.postJSON("/api/v1/generate", map[string]any{"length": 24, "return_value": true})
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Value == nil || len(*resp.Value) != 24 {
		t.Fatal("generate with return_value did not return a 24-character password")
	}
}

// TestPlainTextClientGetsOnlyTheLink covers the contract the shell one-liners
// rely on: a command-line caller receives one line it can hand to a human, with
// nothing to parse and nothing extra to accidentally print.
func TestPlainTextClientGetsOnlyTheLink(t *testing.T) {
	ts := newTestServer(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/secret", strings.NewReader("piped-secret"))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Accept", "text/plain")
	r.Header.Set("User-Agent", "curl/8.7.1")
	w := ts.do(r)

	if w.Code != http.StatusCreated {
		t.Fatalf("returned %d: %s", w.Code, w.Body.String())
	}
	body := strings.TrimSpace(w.Body.String())
	if strings.Count(body, "\n") != 0 {
		t.Fatalf("plain-text response spans several lines:\n%s", body)
	}
	if !strings.HasPrefix(body, "https://onetime.example/s/") || !strings.Contains(body, "#") {
		t.Fatalf("plain-text response is not a link with a fragment: %q", body)
	}
	if strings.Contains(body, "piped-secret") {
		t.Fatal("the create response echoed the secret back")
	}
}

func TestSecretInQueryIsRejected(t *testing.T) {
	ts := newTestServer(t)
	for _, param := range []string{"secret", "password", "passphrase", "value", "key", "token"} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/secret?"+param+"=hunter2", strings.NewReader(""))
		w := ts.do(r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("?%s= returned %d, want 400", param, w.Code)
		}
		if !strings.Contains(w.Body.String(), "compromised") {
			t.Errorf("?%s= did not tell the caller to rotate the value: %s", param, w.Body.String())
		}
	}
}

func TestOversizedTextIsRejected(t *testing.T) {
	ts := newTestServer(t)
	big := strings.Repeat("a", int(ts.cfg.MaxTextBytes)+1)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/secret", strings.NewReader(big))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Accept", "application/json")
	if w := ts.do(r); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("returned %d, want 413", w.Code)
	}
}

func TestFileUploadDownloadOverHTTP(t *testing.T) {
	ts := newTestServer(t)
	payload := bytes.Repeat([]byte("file-content-"), 20000) // spans several chunks

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("ttl_days", "7")
	part, err := mw.CreateFormFile("file", "report.pdf")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/api/v1/secret/file", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Accept", "application/json")
	w := ts.do(r)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload returned %d: %s", w.Code, w.Body.String())
	}
	var created createdResponse
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Kind != "file" || created.Filename != "report.pdf" {
		t.Fatalf("unexpected upload response: %+v", created)
	}

	w = ts.postJSON("/api/v1/reveal", map[string]any{"key": fragmentOf(t, created.SecretURL), "confirm": true})
	if w.Code != http.StatusOK {
		t.Fatalf("reveal returned %d: %s", w.Code, w.Body.String())
	}
	var revealed revealResponse
	_ = json.Unmarshal(w.Body.Bytes(), &revealed)

	dl := httptest.NewRequest(http.MethodGet, "/api/v1/download", nil)
	dl.Header.Set("X-Onetime-Ticket", revealed.DownloadTicket)
	dw := ts.do(dl)
	if dw.Code != http.StatusOK {
		t.Fatalf("download returned %d: %s", dw.Code, dw.Body.String())
	}
	if got := dw.Body.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("downloaded %d bytes, uploaded %d, and they differ", len(got), len(payload))
	}

	// An uploaded file must never come back with its own content type, or an
	// uploaded .html becomes stored cross-site scripting.
	if ct := dw.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q, want application/octet-stream", ct)
	}
	if dw.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("download is missing X-Content-Type-Options: nosniff")
	}
	if !strings.Contains(dw.Header().Get("Content-Disposition"), `filename="report.pdf"`) {
		t.Fatalf("Content-Disposition = %q", dw.Header().Get("Content-Disposition"))
	}
}

func TestDownloadRejectsHeaderInjectionInFilename(t *testing.T) {
	ts := newTestServer(t)
	nasty := "evil\r\nX-Injected: yes\".pdf"

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("filename", nasty)
	part, _ := mw.CreateFormFile("file", "placeholder.bin")
	_, _ = part.Write([]byte("data"))
	_ = mw.Close()

	r := httptest.NewRequest(http.MethodPost, "/api/v1/secret/file", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Accept", "application/json")
	w := ts.do(r)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload returned %d: %s", w.Code, w.Body.String())
	}
	var created createdResponse
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	w = ts.postJSON("/api/v1/reveal", map[string]any{"key": fragmentOf(t, created.SecretURL), "confirm": true})
	var revealed revealResponse
	_ = json.Unmarshal(w.Body.Bytes(), &revealed)

	dl := httptest.NewRequest(http.MethodGet, "/api/v1/download", nil)
	dl.Header.Set("X-Onetime-Ticket", revealed.DownloadTicket)
	dw := ts.do(dl)

	if dw.Header().Get("X-Injected") != "" {
		t.Fatal("a filename injected a response header")
	}
	if cd := dw.Header().Get("Content-Disposition"); strings.ContainsAny(cd, "\r\n") {
		t.Fatalf("Content-Disposition contains a line break: %q", cd)
	}
}

func TestNoCORSHeadersAnywhere(t *testing.T) {
	ts := newTestServer(t)
	key, _ := ts.createText(t, "x", "")

	for _, w := range []*httptest.ResponseRecorder{
		ts.postJSON("/api/v1/peek", map[string]any{"key": key}),
		ts.postJSON("/api/v1/secret", map[string]any{"secret": "y"}),
		ts.do(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)),
	} {
		if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "" {
			t.Fatalf("a response advertised Access-Control-Allow-Origin: %q", origin)
		}
	}
}

// TestNoSecretMaterialInLogs is the automated backstop for the promise that a
// secret never reaches a log line. It drives a full lifecycle at debug level
// with a distinctive marker in every position a secret can occupy, then asserts
// none of it appears in the captured output.
func TestNoSecretMaterialInLogs(t *testing.T) {
	const canary = "CANARY-b7f3e91a-DO-NOT-LOG"
	const passCanary = "PASS-" + canary

	ts := newTestServer(t)
	key, receiptKey := ts.createText(t, canary, passCanary)

	ts.postJSON("/api/v1/peek", map[string]any{"key": key})
	ts.postJSON("/api/v1/reveal", map[string]any{"key": key, "confirm": true, "passphrase": "wrong-" + canary})
	ts.postJSON("/api/v1/reveal", map[string]any{"key": key, "confirm": true, "passphrase": passCanary})
	ts.postJSON("/api/v1/receipt", map[string]any{"key": receiptKey})
	// A path that panics must not dump the request either.
	ts.postJSON("/api/v1/secret", map[string]any{"secret": canary})

	logged := ts.log.String()
	for name, needle := range map[string]string{
		"plaintext":   canary,
		"passphrase":  passCanary,
		"secret key":  key,
		"receipt key": receiptKey,
	} {
		if strings.Contains(logged, needle) {
			t.Errorf("%s leaked into the log output", name)
		}
	}
}

func TestParseTTL(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"14", 14, false},
		{"14d", 14, false},
		{"336h", 14, false},
		{"1h", 1, false}, // anything under a day rounds up to the shortest we support
		{"garbage", 0, true},
		{"14x", 0, true},
	} {
		got, err := parseTTL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseTTL(%q) succeeded, want an error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTTL(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTTL(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestConfigEndpointReportsLiveLimits(t *testing.T) {
	ts := newTestServer(t)
	w := ts.do(httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("config returned %d", w.Code)
	}
	var cfg configResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.MaxFileBytes != ts.cfg.MaxFileBytes || cfg.TTLDefaultDay != ts.cfg.TTLDefaultDays {
		t.Fatalf("config endpoint does not match the running configuration: %+v", cfg)
	}
}

func TestProblemResponsesCarryStableCodes(t *testing.T) {
	ts := newTestServer(t)
	w := ts.postJSON("/api/v1/peek", map[string]any{"key": "nonexistent-key-value-here"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("returned %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var p httpx.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Code != httpx.CodeNotFound {
		t.Fatalf("code = %q, want %q", p.Code, httpx.CodeNotFound)
	}
	if w.Header().Get("X-Onetime-Docs") == "" {
		t.Error("error response does not point at the documentation")
	}
}

// TestConcurrentRevealsProduceOneWinner drives the atomic claim through the
// full HTTP stack, which is where a caching or pooling mistake would show up
// that the store-level test cannot see.
func TestConcurrentRevealsProduceOneWinner(t *testing.T) {
	ts := newTestServer(t)
	key, _ := ts.createText(t, "only-once", "")

	const racers = 25
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		ok    int
	)
	start.Add(1)
	done.Add(racers)
	for range racers {
		go func() {
			defer done.Done()
			start.Wait()
			w := ts.postJSON("/api/v1/reveal", map[string]any{"key": key, "confirm": true})
			mu.Lock()
			defer mu.Unlock()
			if w.Code == http.StatusOK {
				ok++
			}
		}()
	}
	start.Done()
	done.Wait()

	if ok != 1 {
		t.Fatalf("%d concurrent reveals succeeded, want exactly 1", ok)
	}
}

func TestReadLimitedRejectsOversized(t *testing.T) {
	if _, err := readLimited(strings.NewReader("abcdef"), 3); err == nil {
		t.Fatal("readLimited accepted a body over the limit")
	}
	got, err := readLimited(strings.NewReader("abc"), 3)
	if err != nil {
		t.Fatalf("readLimited: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("readLimited returned %q", got)
	}
}
