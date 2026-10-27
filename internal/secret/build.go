package secret

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/digitooai/onetime/internal/blob"
	"github.com/digitooai/onetime/internal/crypto"
	"github.com/digitooai/onetime/internal/store"
)

// build holds the in-flight state of a secret being created. It exists so that
// the text and file paths share one definition of what a new record looks like.
type build struct {
	key      crypto.Key
	metaKey  crypto.Key
	dek      crypto.DEK
	keyID    string
	secret   *store.Secret
	receipt  *store.Receipt
	filename string
	ttlDays  int
}

func (s *Service) newBuild(ttlDays int, pass crypto.Passphrase) (*build, error) {
	if ttlDays != 0 && (ttlDays < s.cfg.TTLMinDays || ttlDays > s.cfg.TTLMaxDays) {
		return nil, ErrBadTTL
	}
	days := s.cfg.TTLFor(ttlDays)

	key, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	metaKey, err := crypto.NewKey()
	if err != nil {
		return nil, err
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	dek, err := crypto.NewDEK()
	if err != nil {
		return nil, err
	}

	keyID := s.deriver.Ring().ActiveID()
	sid := key.SecretID()
	params := s.deriver.Params()

	kek, err := s.deriver.KEK(keyID, key, pass, salt, params)
	if err != nil {
		return nil, err
	}
	wrapped, err := crypto.WrapDEK(kek, dek, crypto.AAD("wrap", sid, keyID))
	if err != nil {
		return nil, err
	}

	now := s.now().UTC().Truncate(time.Second)
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	receiptExpires := expires.Add(s.cfg.ReceiptExtraTTL)

	b := &build{
		key: key, metaKey: metaKey, dek: dek, keyID: keyID, ttlDays: days,
		secret: &store.Secret{
			State:      store.StateNew,
			Kind:       store.KindText,
			Alg:        store.AlgV1,
			KeyID:      keyID,
			Salt:       salt,
			WrappedDEK: wrapped,
			HasPass:    !pass.Empty(),
			ReceiptID:  metaKey.ReceiptID(),
			Created:    now,
			Expires:    expires,
		},
		receipt: &store.Receipt{
			State:         store.StateNew,
			Kind:          store.KindText,
			SecretID:      sid,
			HasPass:       !pass.Empty(),
			Created:       now,
			SecretExpires: expires,
			Expires:       receiptExpires,
		},
	}
	// Only record the KDF cost when a passphrase makes it relevant, so that
	// changing the server's cost settings later does not strand old records.
	if !pass.Empty() {
		b.secret.KDFParams = params.String()
	}
	return b, nil
}

func (b *build) payloadAAD() []byte { return crypto.AAD("payload", b.key.SecretID(), b.keyID) }
func (b *build) metaAAD() []byte    { return crypto.AAD("meta", b.key.SecretID(), b.keyID) }

func (b *build) created(baseURL string) *Created {
	return &Created{
		SecretURL:        baseURL + "/s/" + b.key.SecretID() + "#" + b.key.Encode(),
		ReceiptURL:       baseURL + "/m/" + b.metaKey.ReceiptID() + "#" + b.metaKey.Encode(),
		Kind:             b.secret.Kind,
		Filename:         b.filename,
		Size:             b.secret.PlainSize,
		HasPassphrase:    b.secret.HasPass,
		ExpiresAt:        b.secret.Expires,
		ReceiptExpiresAt: b.receipt.Expires,
		TTLDays:          b.ttlDays,
	}
}

// writeBlob streams a payload to the volume through the stream cipher.
func (s *Service) writeBlob(ctx context.Context, b *build, write func(io.Writer) error) error {
	id, err := blob.NewID()
	if err != nil {
		return err
	}
	meta := blob.Sidecar{
		SecretID: b.key.SecretID(),
		Created:  b.secret.Created.Unix(),
		Expires:  b.secret.Expires.Unix(),
	}
	encSize, err := s.blobs.Create(id, meta, func(w io.Writer) error {
		sw, writerErr := crypto.NewStreamWriter(b.dek, w, b.payloadAAD())
		if writerErr != nil {
			return writerErr
		}
		if writeErr := write(sw); writeErr != nil {
			return writeErr
		}
		return sw.Close()
	})
	if err != nil {
		return fmt.Errorf("secret: store payload: %w", err)
	}
	b.secret.Blob = id
	b.secret.EncSize = encSize
	_ = ctx
	return nil
}

// commit writes the records to Redis.
//
// The blob is already on disk by this point, and that ordering is deliberate.
// Writing Redis first would leave records pointing at files that do not exist,
// which fails at the worst possible moment — when the recipient tries to read.
// This way the worst case is a file nobody references, which the collector
// quietly reclaims.
func (s *Service) commit(ctx context.Context, b *build) error {
	secretTTL := time.Until(b.secret.Expires)
	receiptTTL := time.Until(b.receipt.Expires)
	if err := s.store.CreateSecret(ctx, b.key.SecretID(), b.metaKey.ReceiptID(), b.secret, b.receipt, secretTTL, receiptTTL); err != nil {
		return err
	}
	if b.secret.Blob != "" {
		if err := s.store.ScheduleBlob(ctx, b.secret.Blob, b.secret.Expires); err != nil {
			return err
		}
		if err := s.store.AddDiskUsage(ctx, b.secret.EncSize); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeFilename reduces a client-supplied name to something safe to store
// and to echo back in a Content-Disposition header.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	// Strip any path the client sent: only the final component is a filename,
	// and "../../etc/passwd" is not a filename at all.
	name = filepath.Base(filepath.FromSlash(name))
	name = strings.ReplaceAll(name, "\\", "")
	if name == "." || name == ".." || name == string(filepath.Separator) {
		return ""
	}
	// Control characters, quotes, newlines and semicolons would let a filename
	// inject into a response header.
	name = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '"' || r == ';' || unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	for len(name) > 255 {
		_, size := utf8DecodeLast(name)
		name = name[:len(name)-size]
	}
	return name
}

func utf8DecodeLast(s string) (rune, int) {
	for i := len(s) - 1; i >= 0 && i > len(s)-5; i-- {
		if s[i]&0xC0 != 0x80 {
			return rune(s[i]), len(s) - i
		}
	}
	return 0, 1
}
