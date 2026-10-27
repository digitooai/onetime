package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/digitooai/onetime/internal/secret"
)

// createRequest is the JSON body for creating a text secret.
type createRequest struct {
	Secret     string `json:"secret"`
	TTLDays    int    `json:"ttl_days"`
	Passphrase string `json:"passphrase"`
}

// generateRequest asks the server to invent a password.
type generateRequest struct {
	Length     int    `json:"length"`
	Alphabet   string `json:"alphabet"`
	TTLDays    int    `json:"ttl_days"`
	Passphrase string `json:"passphrase"`
	// ReturnValue defaults to false so that a caller which only needs to hand
	// the link to a human never receives the password at all.
	ReturnValue bool `json:"return_value"`
}

// keyRequest is the body shape shared by every endpoint that addresses an
// existing record. The key travels in the body, never the URL, so it cannot
// end up in an access log, a referrer header or browser history.
type keyRequest struct {
	Key        string `json:"key"`
	Passphrase string `json:"passphrase"`
	Confirm    bool   `json:"confirm"`
}

// createdResponse is returned by every creation endpoint.
type createdResponse struct {
	SecretURL        string  `json:"secret_url"`
	ReceiptURL       string  `json:"receipt_url"`
	Kind             string  `json:"kind"`
	Filename         string  `json:"filename,omitempty"`
	Size             int64   `json:"size"`
	HasPassphrase    bool    `json:"has_passphrase"`
	ExpiresAt        string  `json:"expires_at"`
	ReceiptExpiresAt string  `json:"receipt_expires_at"`
	TTLDays          int     `json:"ttl_days"`
	Value            *string `json:"value,omitempty"`
}

func newCreatedResponse(c *secret.Created) createdResponse {
	return createdResponse{
		SecretURL:        c.SecretURL,
		ReceiptURL:       c.ReceiptURL,
		Kind:             c.Kind,
		Filename:         c.Filename,
		Size:             c.Size,
		HasPassphrase:    c.HasPassphrase,
		ExpiresAt:        c.ExpiresAt.UTC().Format(time.RFC3339),
		ReceiptExpiresAt: c.ReceiptExpiresAt.UTC().Format(time.RFC3339),
		TTLDays:          c.TTLDays,
	}
}

// peekResponse describes a waiting secret without consuming it.
type peekResponse struct {
	Exists        bool   `json:"exists"`
	State         string `json:"state"`
	Kind          string `json:"kind"`
	HasPassphrase bool   `json:"has_passphrase"`
	Size          int64  `json:"size"`
	ExpiresAt     string `json:"expires_at"`
	// Omitted unless the link is protected, so an unprotected one does not
	// carry a field that reads as "zero attempts left".
	AttemptsLeft *int `json:"attempts_left,omitempty"`
}

// revealResponse is a consumed secret.
type revealResponse struct {
	Kind            string `json:"kind"`
	Value           string `json:"value,omitempty"`
	Filename        string `json:"filename,omitempty"`
	Size            int64  `json:"size"`
	DownloadURL     string `json:"download_url,omitempty"`
	DownloadTicket  string `json:"download_ticket,omitempty"`
	TicketExpiresIn int    `json:"ticket_expires_in,omitempty"`
	RevealedAt      string `json:"revealed_at"`
}

// receiptResponse is the sender's view of what happened.
type receiptResponse struct {
	State              string `json:"state"`
	Kind               string `json:"kind"`
	Size               int64  `json:"size"`
	HasPassphrase      bool   `json:"has_passphrase"`
	CreatedAt          string `json:"created_at"`
	SecretExpiresAt    string `json:"secret_expires_at"`
	PeekedAt           string `json:"peeked_at,omitempty"`
	ConsumedAt         string `json:"consumed_at,omitempty"`
	PassphraseFailures int    `json:"passphrase_failures"`
	ReceiptExpiresAt   string `json:"receipt_expires_at"`
}

func newReceiptResponse(s *secret.Status) receiptResponse {
	return receiptResponse{
		State:              s.State,
		Kind:               s.Kind,
		Size:               s.Size,
		HasPassphrase:      s.HasPassphrase,
		CreatedAt:          rfc3339(s.CreatedAt),
		SecretExpiresAt:    rfc3339(s.SecretExpiresAt),
		PeekedAt:           rfc3339(s.PeekedAt),
		ConsumedAt:         rfc3339(s.ConsumedAt),
		PassphraseFailures: s.PassphraseFails,
		ReceiptExpiresAt:   rfc3339(s.ReceiptExpiresAt),
	}
}

// configResponse advertises the live limits so the UI and any client can show
// the truth rather than a hard-coded guess that drifts.
type configResponse struct {
	MaxFileBytes  int64 `json:"max_file_bytes"`
	MaxTextBytes  int64 `json:"max_text_bytes"`
	TTLMinDays    int   `json:"ttl_min_days"`
	TTLMaxDays    int   `json:"ttl_max_days"`
	TTLDefaultDay int   `json:"ttl_default_days"`
	FilesEnabled  bool  `json:"files_enabled"`
	ReadOnly      bool  `json:"read_only"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// parseTTL accepts a retention expressed as a plain number of days ("14"), a
// day suffix ("14d") or a duration ("336h"), because those are all shapes a
// person writing a curl command will reach for.
func parseTTL(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(days))
		if err != nil {
			return 0, fmt.Errorf("cannot read %q as a number of days", s)
		}
		return n, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("cannot read %q as a retention; use days (14) or a duration (336h)", s)
	}
	days := int(d.Hours() / 24)
	if days < 1 && d > 0 {
		days = 1 // anything under a day rounds up to the shortest we support
	}
	return days, nil
}
