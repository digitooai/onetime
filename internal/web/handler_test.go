package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/i18n"
)

func newDiscardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := New(&config.Config{
		BaseURL:     "https://onetime.example",
		DefaultLang: "cs",
		EnableFiles: true,
	}, newDiscardLogger())
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// TestLanguageRedirectTargetsAServedPath covers the negotiation feeding the
// language redirects. ?lang=EN names a supported language, but /EN/ is not a
// route this service registers: echoing the visitor's spelling back into the
// Location header sent them to a 404 by way of a 302. Every case here asserts
// the target is the canonical code, whatever spelling arrived.
func TestLanguageRedirectTargetsAServedPath(t *testing.T) {
	mux := newTestHandler(t)
	for _, tc := range []struct {
		name   string
		query  string
		accept string
		want   string
	}{
		{"canonical spelling", "?lang=en", "", "/en/"},
		{"upper case", "?lang=EN", "", "/en/"},
		{"mixed case with padding", "?lang=+Cs+", "", "/cs/"},
		{"unsupported language falls back", "?lang=de", "", "/cs/"},
		{"no choice, browser preference honoured", "", "en-GB,en;q=0.9", "/en/"},
		{"no choice and no preference", "", "", "/cs/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/"+tc.query, nil)
			if tc.accept != "" {
				r.Header.Set("Accept-Language", tc.accept)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			if got := w.Header().Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLanguageRedirectCannotLeaveTheSite is the reason the negotiation returns
// i18n's own constants rather than a cleaned-up copy of the input. The language
// code is concatenated straight into a Location header, so a value that
// survived validation while still beginning with a slash would turn this into
// an open redirect: "//evil.example" is a scheme-relative URL, and browsers
// follow it off-site.
func TestLanguageRedirectCannotLeaveTheSite(t *testing.T) {
	mux := newTestHandler(t)
	for _, hostile := range []string{
		"//evil.example",
		"/\\evil.example",
		"https://evil.example",
		"cs.evil.example",
		"cs/../../evil",
	} {
		t.Run(hostile, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			q := r.URL.Query()
			q.Set("lang", hostile)
			r.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if got := w.Header().Get("Location"); got != "/cs/" {
				t.Errorf("Location = %q, want the default %q", got, "/cs/")
			}
		})
	}
}

// TestUnprefixedPageRedirectsToALanguage covers the other redirect built the
// same way, so the guarantee is not tested in only one of the two places.
func TestUnprefixedPageRedirectsToALanguage(t *testing.T) {
	mux := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/privacy?lang=EN", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if got := w.Header().Get("Location"); got != "/en/privacy" {
		t.Errorf("Location = %q, want %q", got, "/en/privacy")
	}
}

// The <title> is what a chat client prints on the unfurl card, so it is the one
// line of this service most recipients read first. The generic status-page
// title is wrong there — it describes a dead end, and the link is not one.
func TestUnfurlCardCarriesThePreviewTitle(t *testing.T) {
	mux := newTestHandler(t)
	for _, tc := range []struct {
		name, path, accept, want string
	}{
		{"secret cs", "/s/abcdefghijklmnop", "cs", i18n.T("cs", "status.preview.page_title")},
		{"secret en", "/s/abcdefghijklmnop", "en", i18n.T("en", "status.preview.page_title")},
		{"receipt cs", "/m/abcdefghijklmnop", "cs", i18n.T("cs", "status.preview.page_title")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.Header.Set("User-Agent", "Slackbot-LinkExpanding 1.0")
			r.Header.Set("Accept-Language", tc.accept)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)

			if want := "<title>" + tc.want + "</title>"; !strings.Contains(w.Body.String(), want) {
				t.Errorf("body does not contain %q", want)
			}
		})
	}
}
