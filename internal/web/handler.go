// Package web serves the browser-facing pages.
//
// Every page here is a shell. The pages that deal with a secret never receive
// one: the decryption key lives in the URL fragment, which the browser does not
// transmit, so the server renders the page knowing only that some record was
// asked about. The page then asks the API for what it needs. That is what makes
// a link preview bot harmless — it can fetch the shell all it likes and there
// is nothing there to consume.
package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	webassets "github.com/digitooai/onetime/web"

	"github.com/digitooai/onetime/internal/config"
	"github.com/digitooai/onetime/internal/httpx"
	"github.com/digitooai/onetime/internal/i18n"
)

const langCookie = "lang"

// Handler renders the web UI.
//
// Templates are parsed once per language rather than once in total. Template
// functions are bound at parse time, and size formatting differs by language
// (Czech writes 52,4 MB), so a single template set would have to either clone
// itself on every request or format numbers in only one language.
type Handler struct {
	cfg    *config.Config
	tmpl   map[string]*template.Template
	assets *assets
	log    *slog.Logger
	llms   llmsDoc
}

// New parses the templates and prepares the asset index.
func New(cfg *config.Config, log *slog.Logger) (*Handler, error) {
	static, err := fs.Sub(webassets.Static, "static")
	if err != nil {
		return nil, err
	}
	h := &Handler{cfg: cfg, assets: newAssets(static), log: log, tmpl: map[string]*template.Template{}}

	for _, lang := range i18n.Supported() {
		tmpl, err := template.New("").Funcs(template.FuncMap{
			"bytes": func(n int64) string { return humanBytes(n, lang) },
			"asset": h.assets.URL,
		}).ParseFS(webassets.Templates, "templates/*.gohtml")
		if err != nil {
			return nil, fmt.Errorf("web: parse templates for %q: %w", lang, err)
		}
		h.tmpl[lang] = tmpl
	}
	return h, nil
}

// templatesFor returns the template set for a language, falling back to the
// configured default rather than failing to render.
func (h *Handler) templatesFor(lang string) *template.Template {
	if t, ok := h.tmpl[lang]; ok {
		return t
	}
	return h.tmpl[h.cfg.DefaultLang]
}

// Register mounts the browser routes.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /static/", http.HandlerFunc(h.assets.ServeHTTP))

	mux.HandleFunc("GET /{$}", h.handleRoot)
	mux.HandleFunc("GET /s/{id}", h.handleGate)
	mux.HandleFunc("GET /m/{id}", h.handleReceipt)
	mux.HandleFunc("GET /llms.txt", h.handleLLMs)
	mux.HandleFunc("GET /robots.txt", h.handleRobots)
	mux.HandleFunc("GET /.well-known/llms.txt", h.handleLLMs)
	mux.HandleFunc("GET /api/v1/openapi.json", h.handleOpenAPI)
	mux.HandleFunc("GET /api/docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/llms.txt", http.StatusFound)
	})

	// Unprefixed aliases. These are the shapes people type and paste; without
	// them the language prefix becomes something a visitor has to know about.
	// Both spellings, so neither shape costs the visitor an extra round trip:
	// registering only the trailing-slash pattern makes ServeMux bounce /api to
	// /api/ before we ever get to redirect it onward.
	mux.HandleFunc("GET /api", h.redirectToLang("api"))
	mux.HandleFunc("GET /api/{$}", h.redirectToLang("api"))
	mux.HandleFunc("GET /privacy", h.redirectToLang("privacy"))
	mux.HandleFunc("GET /privacy/{$}", h.redirectToLang("privacy"))

	for _, lang := range i18n.Supported() {
		mux.HandleFunc("GET /"+lang+"/{$}", h.page("create"))
		mux.HandleFunc("GET /"+lang+"/api", h.page("api"))
		mux.HandleFunc("GET /"+lang+"/privacy", h.page("privacy"))
	}
}

// handleRoot sends a browser to its language and a command-line client straight
// to the usage text. Someone who runs `curl https://onetime.digitoo.ai`
// almost certainly wants to know how to use it, not an HTML page.
func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if httpx.PrefersPlainText(r) {
		h.handleLLMs(w, r)
		return
	}
	// h.language returns one of i18n's own language constants — never a string
	// derived from the request — so the target is picked from a fixed set of
	// two and cannot be steered into a scheme-relative "//evil" or an absolute
	// URL. See the note on language for why that guarantee is explicit.
	//nolint:gosec // G710: the target comes from i18n's fixed language set, not from request data
	http.Redirect(w, r, "/"+h.language(r)+"/", http.StatusFound)
}

// redirectToLang sends an unprefixed page URL to the visitor's language.
func (h *Handler) redirectToLang(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// page is a compile-time constant from Register and h.language returns
		// one of i18n's language constants, so both halves of this target are
		// fixed strings rather than request data.
		//nolint:gosec // G710: both path segments come from fixed sets, not from request data
		http.Redirect(w, r, "/"+h.language(r)+"/"+page, http.StatusFound)
	}
}

func (h *Handler) page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lang := h.languageFromPath(r)
		h.render(w, r, name, lang, map[string]any{"Page": name})
	}
}

// handleGate renders the recipient page.
//
// The record id in the path is only used to build the API calls the page makes;
// the server does not look it up. Rendering without a lookup means this route
// stays cheap and, more importantly, entirely side-effect free.
func (h *Handler) handleGate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !plausibleID(id) {
		h.Status(w, r, "not_found", http.StatusNotFound)
		return
	}
	if httpx.IsPreviewBot(r.UserAgent()) {
		// Give an unfurler a neutral page with no hint of what is inside.
		h.renderPreview(w, r)
		return
	}
	h.render(w, r, "gate", h.language(r), map[string]any{
		"Page":     "gate",
		"SecretID": id,
	})
}

func (h *Handler) handleReceipt(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !plausibleID(id) {
		h.Status(w, r, "not_found", http.StatusNotFound)
		return
	}
	if httpx.IsPreviewBot(r.UserAgent()) {
		h.renderPreview(w, r)
		return
	}
	h.render(w, r, "receipt", h.language(r), map[string]any{
		"Page":      "receipt",
		"ReceiptID": id,
	})
}

// Status renders the shared empty-state page.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request, variant string, code int) {
	w.WriteHeader(code)
	h.render(w, r, "status", h.language(r), map[string]any{
		"Page":    "status",
		"Variant": variant,
	})
}

// renderPreview answers a link unfurler with a page that says nothing about
// the secret. The preview still looks like a real service, so a recipient
// seeing it in a chat client has a reason to trust the link.
func (h *Handler) renderPreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	lang := h.language(r)
	// An unfurler shows the <title>, so the card gets the preview's own wording
	// rather than the generic status-page title.
	h.render(w, r, "status", lang, map[string]any{
		"Page":    "status",
		"Variant": "preview",
		"Title":   i18n.T(lang, "status.preview.page_title"),
	})
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, page, lang string, extra map[string]any) {
	data := h.baseData(r, lang)
	// Every page has its own title key; fall back to the site name rather than
	// rendering a raw key if one is ever missing. extra is merged afterwards so
	// that a caller can override the title for one particular render.
	if title := i18n.T(lang, page+".title"); title != "" && title != page+".title" {
		data["Title"] = title
	}
	for k, v := range extra {
		data[k] = v
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl := h.templatesFor(lang)
	name := page + ".gohtml"
	if tmpl == nil || tmpl.Lookup(name) == nil {
		h.log.Error("template missing", "template", name, "lang", lang)
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		// The response is already partly written by this point, so there is no
		// clean error page to fall back to; log it and let the body truncate.
		h.log.Error("template render failed", "template", name, "error", err)
	}
}

func (h *Handler) baseData(r *http.Request, lang string) map[string]any {
	t := i18n.Translator(lang)
	return map[string]any{
		"Lang":         lang,
		"T":            t,
		"Title":        t("site.title"),
		"BaseURL":      h.cfg.BaseURL,
		"Version":      Version,
		"Nonce":        httpx.NonceFrom(r.Context()),
		"AltLangURL":   altLangURL(r, lang),
		"AltLang":      otherLang(lang),
		"CSS":          h.assets.URL("css/app.css"),
		"JS":           h.assets.URL("js/app.js"),
		"I18nJSON":     template.JS(i18n.JSONFor(lang)), //nolint:gosec // catalogue is static, not user input
		"MaxFileBytes": h.cfg.MaxFileBytes,
		"MaxTextBytes": h.cfg.MaxTextBytes,
		"TTLMin":       h.cfg.TTLMinDays,
		"TTLMax":       h.cfg.TTLMaxDays,
		"TTLDefault":   h.cfg.TTLDefaultDays,
		"FilesEnabled": h.cfg.EnableFiles,
		"ReadOnly":     h.cfg.ReadOnly,
		// The gate counts down passphrase attempts, and the limit is
		// configurable, so it cannot be a literal in the script.
		"PassFails": h.cfg.PassphraseWindowFails,
	}
}

// Version is stamped at build time from main.
var Version = "dev"

// language picks the display language: an explicit choice beats the browser's
// preference, which beats the configured default.
//
// Every return is a code i18n vouches for, never the caller's spelling of it.
// ?lang=EN names a supported language but is not a route this service serves,
// and the result is pasted straight into a redirect target, so handing back the
// raw parameter would answer with a 302 to a page that does not exist — and
// would make the redirect target a function of request data.
func (h *Handler) language(r *http.Request) string {
	if lang, ok := i18n.Canonical(r.URL.Query().Get("lang")); ok {
		return lang
	}
	cookie := ""
	if c, err := r.Cookie(langCookie); err == nil {
		cookie = c.Value
	}
	if lang, ok := i18n.Canonical(i18n.Match(r.Header.Get("Accept-Language"), cookie)); ok {
		return lang
	}
	if lang, ok := i18n.Canonical(h.cfg.DefaultLang); ok {
		return lang
	}
	return i18n.DefaultLang
}

// languageFromPath reads the language out of a /{lang}/... route.
func (h *Handler) languageFromPath(r *http.Request) string {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) > 0 {
		if lang, ok := i18n.Canonical(parts[0]); ok {
			return lang
		}
	}
	return h.language(r)
}

func altLangURL(r *http.Request, current string) string {
	other := otherLang(current)
	path := r.URL.Path
	// A recipient link carries no language prefix, and must not gain one: the
	// fragment would be lost on navigation, taking the decryption key with it.
	if strings.HasPrefix(path, "/s/") || strings.HasPrefix(path, "/m/") {
		return "?lang=" + other
	}
	for _, lang := range i18n.Supported() {
		if strings.HasPrefix(path, "/"+lang+"/") || path == "/"+lang {
			return "/" + other + strings.TrimPrefix(path, "/"+lang)
		}
	}
	return "/" + other + "/"
}

func otherLang(current string) string {
	for _, lang := range i18n.Supported() {
		if lang != current {
			return lang
		}
	}
	return current
}

func (h *Handler) handleRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writeBody(w, []byte("User-agent: *\nDisallow: /s/\nDisallow: /m/\nDisallow: /api/\nAllow: /\n"))
}

// writeBody sends a body whose response is already committed: the headers have
// gone out, so a failure cannot be turned into an error page. The realistic
// cause is a visitor who navigated away mid-response, which is not a fault of
// this service and not something it can act on.
func writeBody(w http.ResponseWriter, body []byte) {
	_, _ = w.Write(body) //nolint:errcheck // response already in flight; nothing actionable
}

// plausibleID rejects obviously wrong record ids before rendering, so a
// mistyped link gets the explanatory page rather than a shell that will fail an
// API call a moment later.
func plausibleID(id string) bool {
	if len(id) < 16 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// humanBytes formats a size for the interface language.
//
// Czech writes 2,4 MB and English 2.4 MB. Getting this wrong is small but
// conspicuous: a decimal point in Czech copy reads as a translation nobody
// finished.
//
// Units are binary, and labelled with the familiar kB/MB rather than KiB/MiB.
// That is deliberate. The limit is configured as 52428800 bytes because that is
// a round 50 MiB, and dividing it by 1000 would advertise it as "52.4 MB" — a
// number nobody set and nobody expects. Users asked for a 50 MB limit; this is
// the arithmetic that shows them one.
func humanBytes(n int64, lang string) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	// One decimal, but only where it carries information: "2.4 MB" is useful,
	// "50.0 MB" just makes a round limit look unrounded. This matches the
	// browser-side formatter, which leans on Intl for the same effect.
	size := float64(n) / float64(div)
	value := strings.TrimSuffix(strconv.FormatFloat(size, 'f', 1, 64), ".0")
	if lang == "cs" {
		value = strings.Replace(value, ".", ",", 1)
	}
	return value + " " + []string{"kB", "MB", "GB", "TB"}[exp]
}
