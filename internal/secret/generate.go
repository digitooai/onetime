package secret

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/digitooai/onetime/internal/crypto"
)

// Password alphabets. The unambiguous set omits characters that are easy to
// confuse when a password has to be read aloud down a phone line or copied off
// a screen, which is a real part of how these get delivered.
const (
	alphabetAlnum   = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	alphabetSymbols = alphabetAlnum + "!#%*+-=?@"
	alphabetHex     = "0123456789abcdef"
)

// Password generation limits.
const (
	MinPasswordLen     = 8
	MaxPasswordLen     = 128
	DefaultPasswordLen = 24
)

// GenerateRequest asks the server to invent a password and share it.
type GenerateRequest struct {
	Length     int
	Alphabet   string // alnum | symbols | hex
	TTLDays    int
	Passphrase crypto.Passphrase
	// ReturnValue makes the response include the password itself.
	//
	// It defaults to false, and that default is the entire point of this
	// endpoint. An AI agent asked to "generate a password and put it on the
	// service, don't print it" cannot leak what it never received: with
	// ReturnValue false the value exists only inside this process and inside
	// the encrypted record, never in the agent's transcript, its terminal, or
	// its provider's logs.
	ReturnValue bool
}

// Generated is the outcome of a server-side password generation.
type Generated struct {
	*Created
	// Value is non-empty only when the caller explicitly opted in.
	Value string
}

// Generate invents a password and stores it as a one-time secret.
func (s *Service) Generate(ctx context.Context, req GenerateRequest) (*Generated, error) {
	length := req.Length
	if length == 0 {
		length = DefaultPasswordLen
	}
	if length < MinPasswordLen || length > MaxPasswordLen {
		return nil, fmt.Errorf("%w: length must be between %d and %d", ErrTooLarge, MinPasswordLen, MaxPasswordLen)
	}

	alphabet, err := alphabetFor(req.Alphabet)
	if err != nil {
		return nil, err
	}
	value, err := randomString(length, alphabet)
	if err != nil {
		return nil, err
	}

	created, err := s.CreateText(ctx, CreateTextRequest{
		Text:       []byte(value),
		Passphrase: req.Passphrase,
		TTLDays:    req.TTLDays,
		Source:     "generate",
	})
	if err != nil {
		return nil, err
	}

	out := &Generated{Created: created}
	if req.ReturnValue {
		out.Value = value
	}
	return out, nil
}

func alphabetFor(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "symbols", "alnum-symbols":
		return alphabetSymbols, nil
	case "alnum":
		return alphabetAlnum, nil
	case "hex":
		return alphabetHex, nil
	default:
		return "", fmt.Errorf("%w %q, want alnum, symbols or hex", ErrBadAlphabet, name)
	}
}

// randomString draws from the alphabet without modulo bias.
func randomString(n int, alphabet string) (string, error) {
	max := big.NewInt(int64(len(alphabet)))
	var sb strings.Builder
	sb.Grow(n)
	for range n {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("secret: generate password: %w", err)
		}
		sb.WriteByte(alphabet[idx.Int64()])
	}
	return sb.String(), nil
}
