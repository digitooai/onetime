package api

import (
	"errors"
	"net/http"

	"github.com/digitooai/onetime/internal/httpx"
	"github.com/digitooai/onetime/internal/secret"
)

// problemFor translates a domain error into the wire format.
//
// Each entry pins one behaviour worth being deliberate about. A read link and a
// destroyed link report differently from an unknown one, because the recipient
// genuinely needs to know which happened and a 256-bit id makes the disclosure
// harmless. A missing confirmation and a wrong passphrase both come back
// without consuming anything, so a retry is always possible.
func problemFor(err error) httpx.Problem {
	switch {
	case errors.Is(err, secret.ErrNotFound):
		return httpx.Problem{Status: http.StatusNotFound, Code: httpx.CodeNotFound,
			Title:  "No such link",
			Detail: "Check that the whole link was copied, including everything after the # character."}

	case errors.Is(err, secret.ErrAlreadyRevealed):
		return httpx.Problem{Status: http.StatusGone, Code: httpx.CodeAlreadyRevealed,
			Title:  "This link has already been used",
			Detail: "Someone opened it, which deleted the content. Links here work only once."}

	case errors.Is(err, secret.ErrBurned):
		return httpx.Problem{Status: http.StatusGone, Code: httpx.CodeBurned,
			Title:  "The sender cancelled this link",
			Detail: "They deleted the content before anyone opened it."}

	case errors.Is(err, secret.ErrDestroyed):
		return httpx.Problem{Status: http.StatusGone, Code: httpx.CodeDestroyed,
			Title:  "The content was destroyed",
			Detail: "The passphrase was entered incorrectly too many times, so the content was destroyed."}

	case errors.Is(err, secret.ErrPassphraseRequired):
		return httpx.Problem{Status: http.StatusUnauthorized, Code: httpx.CodePassphraseRequired,
			Title:  "Passphrase required",
			Detail: "This link is protected. Send the passphrase in the request body."}

	case errors.Is(err, secret.ErrBadPassphrase):
		return httpx.Problem{Status: http.StatusForbidden, Code: httpx.CodeBadPassphrase,
			Title:  "Incorrect passphrase",
			Detail: "The content was not consumed; you can try again."}

	case errors.Is(err, secret.ErrTooManyAttempts):
		return httpx.Problem{Status: http.StatusTooManyRequests, Code: httpx.CodeTooManyAttempts,
			Title:  "Too many failed attempts",
			Detail: "Wait a few minutes before trying the passphrase again."}

	case errors.Is(err, secret.ErrConfirmationRequired):
		return httpx.Problem{Status: http.StatusBadRequest, Code: httpx.CodeConfirmationNeeded,
			Title: "Explicit confirmation required",
			Detail: "Revealing destroys the content, so it needs a deliberate action. " +
				`Send {"confirm":true} to proceed.`,
			Example: `printf '{"key":"%s","confirm":true}' "$KEY" | curl -sS -X POST ` +
				`-H 'Content-Type: application/json' --data-binary @- https://onetime.digitoo.ai/api/v1/reveal`}

	case errors.Is(err, secret.ErrTooLarge):
		return httpx.Problem{Status: http.StatusRequestEntityTooLarge, Code: httpx.CodePayloadTooLarge,
			Title: "Payload too large", Detail: err.Error()}

	case errors.Is(err, secret.ErrEmpty):
		return httpx.Problem{Status: http.StatusBadRequest, Code: httpx.CodeEmpty,
			Title: "Nothing to share", Detail: "The request body was empty."}

	case errors.Is(err, secret.ErrBadAlphabet):
		return httpx.Problem{Status: http.StatusBadRequest, Code: httpx.CodeBadRequest,
			Title: "Unknown alphabet", Detail: "alphabet must be alnum, symbols or hex."}

	case errors.Is(err, secret.ErrBadTTL):
		return httpx.Problem{Status: http.StatusBadRequest, Code: httpx.CodeInvalidTTL,
			Title: "Retention out of range", Detail: "ttl_days must be between 1 and 30."}

	case errors.Is(err, secret.ErrStorageFull):
		return httpx.Problem{Status: http.StatusInsufficientStorage, Code: httpx.CodeStorageFull,
			Title:  "Storage full",
			Detail: "The volume is too full to accept another file right now. Text secrets still work."}

	case errors.Is(err, secret.ErrFilesDisabled):
		return httpx.Problem{Status: http.StatusForbidden, Code: httpx.CodeFilesDisabled,
			Title: "File sharing is disabled", Detail: "This deployment accepts text secrets only."}

	case errors.Is(err, secret.ErrReadOnly):
		return httpx.Problem{Status: http.StatusServiceUnavailable, Code: httpx.CodeReadOnly,
			Title:  "Maintenance in progress",
			Detail: "New links cannot be created right now. Existing links still work."}

	case errors.Is(err, secret.ErrQuotaExceeded):
		return httpx.Problem{Status: http.StatusTooManyRequests, Code: httpx.CodeQuotaExceeded,
			Title: "Daily upload quota exceeded", Detail: "Try again tomorrow."}

	case errors.Is(err, secret.ErrTicketExpired):
		return httpx.Problem{Status: http.StatusGone, Code: httpx.CodeTicketExpired,
			Title:  "Download link expired",
			Detail: "A download must start within a few minutes of revealing the secret."}

	default:
		return httpx.Problem{Status: http.StatusInternalServerError, Code: httpx.CodeInternal,
			Title:  "Something broke on our side",
			Detail: "Please try again shortly."}
	}
}

// StatusVariant maps a domain error to the name of a page in the web UI, so
// that the API and the browser describe the same failure identically.
func StatusVariant(err error) string {
	switch {
	case errors.Is(err, secret.ErrAlreadyRevealed):
		return "already_read"
	case errors.Is(err, secret.ErrBurned):
		return "burned"
	case errors.Is(err, secret.ErrDestroyed):
		return "destroyed"
	case errors.Is(err, secret.ErrNotFound):
		return "not_found"
	case errors.Is(err, secret.ErrReadOnly):
		return "read_only"
	case errors.Is(err, secret.ErrTooManyAttempts):
		return "rate_limited"
	default:
		return "server_error"
	}
}
