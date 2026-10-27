package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/httpx"
	"github.com/digitooai/onetime/internal/ratelimit"
	"github.com/digitooai/onetime/internal/secret"
)

// maxFieldBytes caps each scalar multipart field. Nothing legitimate in the
// form is long, and without a cap a client could stream gigabytes into what is
// supposed to be a passphrase.
const maxFieldBytes = 4 << 10

// handleCreateFileStream takes the whole request body as the file.
//
// This is the shape `curl -T file` produces, and it is the one to document:
// -T streams, whereas --data-binary @file loads the entire file into curl's
// memory before sending a byte.
func (s *Server) handleCreateFileStream(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionCreateFile) {
		return
	}
	days, err := ttlFromHeaders(r)
	if err != nil {
		s.badRequest(w, r, err.Error())
		return
	}
	filename := firstNonEmpty(r.URL.Query().Get("filename"), r.Header.Get("X-Onetime-Filename"))

	declared := r.ContentLength
	if !s.checkDeclaredSize(w, r, declared) {
		return
	}
	body, ok := s.limitBody(w, r)
	if !ok {
		return
	}
	if s.svc.QuotaExceeded(r.Context(), s.limiter.Identity(r)) {
		s.fail(w, r, secret.ErrQuotaExceeded)
		return
	}

	created, err := s.svc.CreateFile(r.Context(), secret.CreateFileRequest{
		Filename:   filename,
		Passphrase: crypto.Passphrase(r.Header.Get("X-Onetime-Passphrase")),
		TTLDays:    days,
		Declared:   declared,
		Source:     "api",
	}, body)
	if err != nil {
		s.failUpload(w, r, err)
		return
	}
	s.recordUpload(r, created.Size)
	s.writeCreated(w, r, created, nil)
}

// handleCreateFileMultipart takes a browser form upload.
//
// It reads the parts one at a time rather than calling ParseMultipartForm,
// which would spool the whole file into temporary files of its own choosing —
// outside the volume we control, and on a filesystem we have not promised is
// wiped. The file part must arrive last so that the retention and passphrase
// are known before a single byte is written.
func (s *Server) handleCreateFileMultipart(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, ratelimit.ActionCreateFile) {
		return
	}
	if !s.checkDeclaredSize(w, r, r.ContentLength) {
		return
	}

	if s.svc.QuotaExceeded(r.Context(), s.limiter.Identity(r)) {
		s.fail(w, r, secret.ErrQuotaExceeded)
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		s.badRequest(w, r, "expected a multipart/form-data body")
		return
	}

	req := secret.CreateFileRequest{Source: "web"}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			s.badRequest(w, r, "could not read the multipart body")
			return
		}

		if part.FormName() != "file" {
			value, readErr := io.ReadAll(io.LimitReader(part, maxFieldBytes))
			_ = part.Close()
			if readErr != nil {
				s.badRequest(w, r, "could not read form field "+part.FormName())
				return
			}
			switch part.FormName() {
			case "ttl_days", "ttl":
				days, ttlErr := parseTTL(string(value))
				if ttlErr != nil {
					s.badRequest(w, r, ttlErr.Error())
					return
				}
				req.TTLDays = days
			case "passphrase":
				req.Passphrase = crypto.Passphrase(value)
			case "filename":
				req.Filename = string(value)
			}
			continue
		}

		if req.Filename == "" {
			req.Filename = part.FileName()
		}
		req.Declared = declaredFromPart(r)
		body := http.MaxBytesReader(w, part, s.cfg.MaxFileBytes)
		created, err := s.svc.CreateFile(r.Context(), req, body)
		_ = part.Close()
		if err != nil {
			s.failUpload(w, r, err)
			return
		}
		s.recordUpload(r, created.Size)
		s.writeCreated(w, r, created, nil)
		return
	}

	httpx.WriteProblem(w, r, httpx.Problem{
		Status: http.StatusBadRequest, Code: httpx.CodeBadRequest,
		Title:  "No file in the request",
		Detail: "Send the file as a part named \"file\", and send it last so the other fields are read first.",
	})
}

// checkDeclaredSize rejects an oversized upload from the Content-Length alone,
// before reading any of it, so a 5 GB body is refused in milliseconds rather
// than after five gigabytes have crossed the wire.
func (s *Server) checkDeclaredSize(w http.ResponseWriter, r *http.Request, declared int64) bool {
	if declared > 0 && declared > s.cfg.MaxFileBytes+multipartSlack {
		s.fail(w, r, secret.ErrTooLarge)
		return false
	}
	return true
}

// multipartSlack allows for part headers and boundaries around a file that is
// itself exactly at the limit.
const multipartSlack = 8 << 10

func (s *Server) limitBody(w http.ResponseWriter, r *http.Request) (io.Reader, bool) {
	if !s.cfg.EnableFiles {
		s.fail(w, r, secret.ErrFilesDisabled)
		return nil, false
	}
	return http.MaxBytesReader(w, r.Body, s.cfg.MaxFileBytes), true
}

// failUpload maps the error a truncated stream produces onto the size limit,
// which is what actually happened from the caller's point of view.
func (s *Server) failUpload(w http.ResponseWriter, r *http.Request, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) || strings.Contains(err.Error(), "http: request body too large") {
		s.fail(w, r, secret.ErrTooLarge)
		return
	}
	s.fail(w, r, err)
}

// recordUpload charges an upload against the client's daily byte quota. It is
// deliberately advisory: the request already succeeded, and the quota gates the
// next one.
func (s *Server) recordUpload(r *http.Request, size int64) {
	if size <= 0 || s.cfg.DailyBytesPerIP <= 0 {
		return
	}
	id := s.limiter.Identity(r)
	total, err := s.svc.ChargeUpload(r.Context(), id, size)
	if err != nil {
		s.log.Warn("could not record the upload quota",
			"request_id", httpx.RequestIDFrom(r.Context()), "error", err)
		return
	}
	if total > s.cfg.DailyBytesPerIP {
		s.log.Info("client passed its daily upload quota",
			"identity", id, "bytes_today", total, "limit", s.cfg.DailyBytesPerIP)
	}
}

func declaredFromPart(r *http.Request) int64 {
	if v := r.Header.Get("X-Onetime-Size"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 0
}
