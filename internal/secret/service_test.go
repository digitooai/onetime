package secret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisclient "github.com/redis/go-redis/v9"

	"github.com/digitooai/onetime/internal/blob"
	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/store"
)

type harness struct {
	svc *Service
	mr  *miniredis.Miniredis
	cfg *config.Config
	now time.Time
}

// advance moves both clocks together. miniredis keeps its own notion of time
// for key expiry, and the service reads its own, so a test that moves only one
// of them is testing a state the real system never reaches.
func (h *harness) advance(d time.Duration) {
	h.now = h.now.Add(d)
	h.mr.FastForward(d)
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redisclient.NewClient(&redisclient.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	dir := t.TempDir()
	blobs, err := blob.New(dir+"/blobs", dir+"/tmp")
	if err != nil {
		t.Fatalf("blob.New: %v", err)
	}

	t.Setenv("ONETIME_MASTER_KEYS", "v1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, crypto.MasterKeyLen)))
	t.Setenv("ONETIME_BASE_URL", "https://onetime.example")
	t.Setenv("ONETIME_DATA_DIR", dir+"/blobs")
	t.Setenv("ONETIME_TMP_DIR", dir+"/tmp")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	keys, _ := cfg.MasterKeys()
	ring, err := crypto.ParseKeyring(keys)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	// Cheap KDF parameters keep the suite fast; correctness does not depend on
	// the cost factor.
	deriver := crypto.NewDeriver(ring, crypto.KDFParams{MemKiB: 64, Time: 1, Par: 1}, 2)

	h := &harness{
		svc: New(cfg, store.NewWithClient(client), blobs, deriver, nil),
		mr:  mr,
		cfg: cfg,
		now: time.Now().UTC().Truncate(time.Second),
	}
	h.svc.SetClock(func() time.Time { return h.now })
	return h
}

// fragment extracts the key from a link, the way a browser would.
func fragment(t *testing.T, url string) string {
	t.Helper()
	_, frag, ok := strings.Cut(url, "#")
	if !ok {
		t.Fatalf("link %q has no fragment", url)
	}
	return frag
}

func TestCreateAndRevealText(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("hunter2"), TTLDays: 14})
	if err != nil {
		t.Fatalf("CreateText: %v", err)
	}
	if !strings.Contains(created.SecretURL, "#") || !strings.Contains(created.ReceiptURL, "#") {
		t.Fatalf("links must carry the key in a fragment, got %q", created.SecretURL)
	}
	if created.TTLDays != 14 {
		t.Fatalf("TTLDays = %d, want 14", created.TTLDays)
	}

	key := fragment(t, created.SecretURL)

	info, err := h.svc.Peek(ctx, key)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if info.Kind != store.KindText || info.HasPassphrase || info.Size != 7 {
		t.Fatalf("unexpected peek: %+v", info)
	}

	got, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true})
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if string(got.Text) != "hunter2" {
		t.Fatalf("revealed %q, want hunter2", got.Text)
	}
}

// TestRevealIsSingleUse is the headline promise of the service.
func TestRevealIsSingleUse(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("once")})
	key := fragment(t, created.SecretURL)

	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true}); err != nil {
		t.Fatalf("first reveal: %v", err)
	}
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true}); !errors.Is(err, ErrAlreadyRevealed) {
		t.Fatalf("second reveal error = %v, want ErrAlreadyRevealed", err)
	}
	// A peek after the fact should say the same thing, so the recipient page
	// can explain what happened instead of showing "no such link".
	if _, err := h.svc.Peek(ctx, key); !errors.Is(err, ErrAlreadyRevealed) {
		t.Fatalf("peek after reveal error = %v, want ErrAlreadyRevealed", err)
	}
}

// TestRevealNeedsConfirmation covers the anti-prefetch gate: without an
// explicit confirmation nothing is consumed, so a chat client fetching a link
// preview cannot destroy the secret before a human sees it.
func TestRevealNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("safe")})
	key := fragment(t, created.SecretURL)

	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key}); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("unconfirmed reveal error = %v, want ErrConfirmationRequired", err)
	}
	// And the secret is untouched.
	got, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true})
	if err != nil {
		t.Fatalf("confirmed reveal after a refused one: %v", err)
	}
	if string(got.Text) != "safe" {
		t.Fatalf("revealed %q, want safe", got.Text)
	}
}

// TestBadPassphraseDoesNotBurn is the other half of the reveal ordering: a
// wrong guess must cost the guesser an attempt, never cost the recipient their
// secret.
func TestBadPassphraseDoesNotBurn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, err := h.svc.CreateText(ctx, CreateTextRequest{
		Text:       []byte("protected"),
		Passphrase: crypto.Passphrase("correct horse"),
	})
	if err != nil {
		t.Fatalf("CreateText: %v", err)
	}
	key := fragment(t, created.SecretURL)

	if !created.HasPassphrase {
		t.Fatal("created secret does not report a passphrase")
	}
	if _, revealErr := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true}); !errors.Is(revealErr, ErrPassphraseRequired) {
		t.Fatalf("missing passphrase error = %v, want ErrPassphraseRequired", revealErr)
	}

	for i := range 4 {
		_, attemptErr := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("wrong")})
		if !errors.Is(attemptErr, ErrBadPassphrase) {
			t.Fatalf("attempt %d error = %v, want ErrBadPassphrase", i+1, attemptErr)
		}
	}
	// After four wrong guesses the right one still works.
	got, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("correct horse")})
	if err != nil {
		t.Fatalf("correct passphrase after failures: %v", err)
	}
	if string(got.Text) != "protected" {
		t.Fatalf("revealed %q, want protected", got.Text)
	}
}

func TestPassphraseLockout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{
		Text:       []byte("protected"),
		Passphrase: crypto.Passphrase("right"),
	})
	key := fragment(t, created.SecretURL)

	for range h.cfg.PassphraseWindowFails {
		_, _ = h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("nope")})
	}
	// Now even the correct passphrase is throttled.
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("right")}); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("error during lockout = %v, want ErrTooManyAttempts", err)
	}
	// The window passes and the secret is readable again.
	h.advance(h.cfg.PassphraseWindow + time.Second)
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("right")}); err != nil {
		t.Fatalf("reveal after the lockout window: %v", err)
	}
}

func TestSustainedGuessingDestroysSecret(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{
		Text:       []byte("protected"),
		Passphrase: crypto.Passphrase("right"),
	})
	key := fragment(t, created.SecretURL)

	var lastErr error
	for range h.cfg.PassphraseTotalFails {
		_, lastErr = h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("nope")})
		// Step past the rolling window so the throttle does not mask the total.
		h.advance(h.cfg.PassphraseWindow + time.Second)
	}
	if !errors.Is(lastErr, ErrDestroyed) {
		t.Fatalf("final attempt error = %v, want ErrDestroyed", lastErr)
	}
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true, Passphrase: crypto.Passphrase("right")}); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("reveal after destruction = %v, want ErrDestroyed", err)
	}
}

func TestSenderCanBurnWithoutSeeingContent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("oops")})
	secretKey := fragment(t, created.SecretURL)
	receiptKey := fragment(t, created.ReceiptURL)

	status, err := h.svc.ReceiptStatus(ctx, receiptKey)
	if err != nil {
		t.Fatalf("ReceiptStatus: %v", err)
	}
	if status.State != store.StateNew {
		t.Fatalf("state = %q, want new", status.State)
	}

	burned, err := h.svc.Burn(ctx, receiptKey)
	if err != nil {
		t.Fatalf("Burn: %v", err)
	}
	if burned.State != store.StateBurned {
		t.Fatalf("state after burn = %q, want burned", burned.State)
	}
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: secretKey, Confirm: true}); !errors.Is(err, ErrBurned) {
		t.Fatalf("reveal after burn = %v, want ErrBurned", err)
	}

	// The receipt key must not be usable as a secret key: the sender can
	// destroy their secret, but cannot read it back.
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: receiptKey, Confirm: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revealing with the receipt key = %v, want ErrNotFound", err)
	}
}

func TestPeekRecordsDeliveryForSender(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("hi")})
	if _, err := h.svc.Peek(ctx, fragment(t, created.SecretURL)); err != nil {
		t.Fatalf("Peek: %v", err)
	}
	status, err := h.svc.ReceiptStatus(ctx, fragment(t, created.ReceiptURL))
	if err != nil {
		t.Fatalf("ReceiptStatus: %v", err)
	}
	if status.PeekedAt.IsZero() {
		t.Fatal("peek did not record delivery on the receipt")
	}
	if status.State != store.StateNew {
		t.Fatalf("peek changed the state to %q; it must not consume", status.State)
	}
}

func TestFileRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	payload := make([]byte, 300*1024) // spans several stream chunks
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	created, err := h.svc.CreateFile(ctx, CreateFileRequest{
		Filename: "faktura 2026-08.pdf",
		Declared: int64(len(payload)),
	}, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	if created.Kind != store.KindFile || created.Filename != "faktura 2026-08.pdf" {
		t.Fatalf("unexpected creation: %+v", created)
	}

	// A peek must describe the file without leaking its name: returning the
	// name would mean unwrapping the data key on every page load.
	info, err := h.svc.Peek(ctx, fragment(t, created.SecretURL))
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if info.Kind != store.KindFile || info.Size != int64(len(payload)) {
		t.Fatalf("unexpected peek: %+v", info)
	}

	revealed, err := h.svc.Reveal(ctx, RevealRequest{Key: fragment(t, created.SecretURL), Confirm: true})
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if revealed.Ticket == "" || revealed.Filename != "faktura 2026-08.pdf" {
		t.Fatalf("unexpected reveal: %+v", revealed)
	}

	dl, err := h.svc.OpenDownload(ctx, revealed.Ticket)
	if err != nil {
		t.Fatalf("OpenDownload: %v", err)
	}
	got, err := io.ReadAll(dl.Body)
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if err := dl.Body.Close(); err != nil {
		t.Fatalf("close download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded bytes differ from what was uploaded")
	}
	if dl.Filename != "faktura 2026-08.pdf" {
		t.Fatalf("download filename = %q", dl.Filename)
	}

	// Completing the transfer removes the file from the volume.
	dl.Done(true)
	if _, err := h.svc.OpenDownload(ctx, revealed.Ticket); !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("download after completion = %v, want ErrTicketExpired", err)
	}
}

func TestGenerateKeepsValueFromTheCaller(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The default: the server invents the password and the caller never sees
	// it. This is what lets an agent share a credential it cannot leak.
	gen, err := h.svc.Generate(ctx, GenerateRequest{Length: 24})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if gen.Value != "" {
		t.Fatal("Generate returned the password without being asked to")
	}
	if gen.Size != 24 {
		t.Fatalf("size = %d, want 24", gen.Size)
	}

	revealed, err := h.svc.Reveal(ctx, RevealRequest{Key: fragment(t, gen.SecretURL), Confirm: true})
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if len(revealed.Text) != 24 {
		t.Fatalf("generated password is %d characters, want 24", len(revealed.Text))
	}

	// Opting in returns it, for the case where the agent must also use it.
	gen2, err := h.svc.Generate(ctx, GenerateRequest{Length: 32, ReturnValue: true})
	if err != nil {
		t.Fatalf("Generate with ReturnValue: %v", err)
	}
	if len(gen2.Value) != 32 {
		t.Fatalf("returned password is %d characters, want 32", len(gen2.Value))
	}
}

func TestGenerateRejectsSillyLengths(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, n := range []int{1, MinPasswordLen - 1, MaxPasswordLen + 1} {
		if _, err := h.svc.Generate(ctx, GenerateRequest{Length: n}); err == nil {
			t.Fatalf("Generate(length=%d) succeeded, want a rejection", n)
		}
	}
}

func TestTTLBounds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Zero means "use the default", which is the whole point of hiding the
	// control behind a disclosure in the UI.
	created, err := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("x")})
	if err != nil {
		t.Fatalf("CreateText: %v", err)
	}
	if created.TTLDays != h.cfg.TTLDefaultDays {
		t.Fatalf("default TTL = %d, want %d", created.TTLDays, h.cfg.TTLDefaultDays)
	}

	for _, days := range []int{h.cfg.TTLMaxDays + 1, -5, 9999} {
		if _, err := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("x"), TTLDays: days}); !errors.Is(err, ErrBadTTL) {
			t.Fatalf("CreateText(ttl=%d) error = %v, want ErrBadTTL", days, err)
		}
	}
	for _, days := range []int{h.cfg.TTLMinDays, h.cfg.TTLMaxDays} {
		got, err := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("x"), TTLDays: days})
		if err != nil {
			t.Fatalf("CreateText(ttl=%d): %v", days, err)
		}
		if got.TTLDays != days {
			t.Fatalf("TTLDays = %d, want %d", got.TTLDays, days)
		}
	}
}

func TestRejectsEmptyAndOversized(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	if _, err := h.svc.CreateText(ctx, CreateTextRequest{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty text error = %v, want ErrEmpty", err)
	}
	big := make([]byte, h.cfg.MaxTextBytes+1)
	if _, err := h.svc.CreateText(ctx, CreateTextRequest{Text: big}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized text error = %v, want ErrTooLarge", err)
	}
	if _, err := h.svc.CreateFile(ctx, CreateFileRequest{Declared: h.cfg.MaxFileBytes + 1}, bytes.NewReader(nil)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized file error = %v, want ErrTooLarge", err)
	}
}

func TestLongTextTakesTheStreamingPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Above the inline threshold the payload lands on the volume rather than in
	// Redis, but the caller must not be able to tell the difference.
	text := bytes.Repeat([]byte("a"), int(h.cfg.MaxTextInlineBytes)+1024)
	created, err := h.svc.CreateText(ctx, CreateTextRequest{Text: text})
	if err != nil {
		t.Fatalf("CreateText: %v", err)
	}
	got, err := h.svc.Reveal(ctx, RevealRequest{Key: fragment(t, created.SecretURL), Confirm: true})
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if !bytes.Equal(got.Text, text) {
		t.Fatal("long text did not survive the round trip")
	}
}

func TestUnknownLinkLooksLikeNotFound(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	for _, key := range []string{"", "garbage", strings.Repeat("A", 43)} {
		if _, err := h.svc.Peek(ctx, key); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Peek(%q) error = %v, want ErrNotFound", key, err)
		}
		if _, err := h.svc.Reveal(ctx, RevealRequest{Key: key, Confirm: true}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Reveal(%q) error = %v, want ErrNotFound", key, err)
		}
	}
}

func TestExpiredSecretIsGoneButSenderStillSeesWhy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("x"), TTLDays: 1})
	h.advance(48 * time.Hour)

	if _, err := h.svc.Peek(ctx, fragment(t, created.SecretURL)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("peek on an expired secret = %v, want ErrNotFound", err)
	}
	status, err := h.svc.ReceiptStatus(ctx, fragment(t, created.ReceiptURL))
	if err != nil {
		t.Fatalf("ReceiptStatus: %v", err)
	}
	if status.State != "expired" {
		t.Fatalf("receipt state = %q, want expired", status.State)
	}
}

func TestSanitizeFilename(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd", "passwd"},
		{"/absolute/path.txt", "path.txt"},
		{`quote"and;semicolon.txt`, "quoteandsemicolon.txt"},
		{"line\r\nbreak.txt", "linebreak.txt"},
		{"  spaced.txt  ", "spaced.txt"},
		{"", ""},
		{"..", ""},
		{"účtenka-září.pdf", "účtenka-září.pdf"},
	} {
		if got := sanitizeFilename(tc.in); got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := sanitizeFilename(strings.Repeat("x", 400) + ".pdf"); len(got) > 255 {
		t.Errorf("sanitizeFilename did not cap the length, got %d bytes", len(got))
	}
}

func TestReadOnlyRefusesWritesButAllowsReads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created, _ := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("before maintenance")})
	h.cfg.ReadOnly = true

	if _, err := h.svc.CreateText(ctx, CreateTextRequest{Text: []byte("x")}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("create while read-only = %v, want ErrReadOnly", err)
	}
	// Existing links keep working, which is the point of the switch.
	if _, err := h.svc.Reveal(ctx, RevealRequest{Key: fragment(t, created.SecretURL), Confirm: true}); err != nil {
		t.Fatalf("reveal while read-only: %v", err)
	}
}
