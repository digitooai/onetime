package ratelimit

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/digitooai/onetime/internal/store"
)

// Action names one throttled operation. Separate buckets mean a burst of page
// views cannot starve someone's ability to actually read their secret.
type Action string

const (
	ActionCreateText Action = "create_text"
	ActionCreateFile Action = "create_file"
	ActionGenerate   Action = "generate"
	ActionPeek       Action = "peek"
	ActionReveal     Action = "reveal"
	ActionDownload   Action = "download"
	ActionReceipt    Action = "receipt"
	ActionBurn       Action = "burn"
	ActionPage       Action = "page"
)

// Policy is a sustained rate plus how far ahead of it a caller may run.
type Policy struct {
	// PerHour is the sustained allowance.
	PerHour int
	// Burst is how many requests may arrive back to back.
	Burst int
}

// Interval is the spacing between permitted requests.
func (p Policy) Interval() time.Duration {
	if p.PerHour <= 0 {
		return 0
	}
	return time.Hour / time.Duration(p.PerHour)
}

// DefaultPolicies are tuned for a service humans use a handful of times a day.
// They are generous enough that nobody legitimate will meet them and tight
// enough that nobody turns this into free file hosting.
func DefaultPolicies() map[Action]Policy {
	return map[Action]Policy{
		ActionCreateText: {PerHour: 30, Burst: 10},
		ActionCreateFile: {PerHour: 10, Burst: 3},
		ActionGenerate:   {PerHour: 30, Burst: 10},
		ActionPeek:       {PerHour: 300, Burst: 30},
		ActionReveal:     {PerHour: 120, Burst: 20},
		ActionDownload:   {PerHour: 60, Burst: 10},
		ActionReceipt:    {PerHour: 300, Burst: 30},
		ActionBurn:       {PerHour: 60, Burst: 10},
		ActionPage:       {PerHour: 600, Burst: 60},
	}
}

// GlobalCreatePolicy is a brake for distributed abuse, keyed without an
// identity so it applies across every caller at once.
var GlobalCreatePolicy = Policy{PerHour: 2000, Burst: 200}

// Limiter applies policies against the shared Redis buckets.
type Limiter struct {
	store    *store.Redis
	policies map[Action]Policy
	trusted  []netip.Prefix
	allow    []netip.Prefix
	pepper   []byte
	enabled  bool
}

// New builds a limiter. pepper keys the identity HMAC and should be derived
// from the master key so that identities are not portable between deployments.
func New(st *store.Redis, trusted, allowlist []netip.Prefix, pepper []byte, enabled bool) *Limiter {
	return &Limiter{
		store:    st,
		policies: DefaultPolicies(),
		trusted:  trusted,
		allow:    allowlist,
		pepper:   pepper,
		enabled:  enabled,
	}
}

// SetPolicy overrides one action's allowance.
func (l *Limiter) SetPolicy(a Action, p Policy) { l.policies[a] = p }

// Result reports a limiter decision.
type Result struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Check applies the policy for an action to the request's client.
func (l *Limiter) Check(ctx context.Context, r *http.Request, action Action) (Result, error) {
	if !l.enabled {
		return Result{Allowed: true}, nil
	}
	if addr := clientAddr(r, l.trusted); addr.IsValid() {
		for _, p := range l.allow {
			if p.Contains(addr) {
				return Result{Allowed: true}, nil
			}
		}
	}
	policy, ok := l.policies[action]
	if !ok || policy.PerHour <= 0 {
		return Result{Allowed: true}, nil
	}
	id := Identity(r, l.trusted, l.pepper)
	allowed, retry, err := l.store.Allow(ctx, store.RateLimitKey(string(action), id), policy.Interval(), policy.Burst)
	if err != nil {
		// A limiter that cannot reach Redis must not become an outage. Redis
		// being down already fails the readiness probe; refusing every request
		// on top of that helps nobody.
		return Result{Allowed: true}, err
	}
	return Result{Allowed: allowed, RetryAfter: retry}, nil
}

// CheckGlobal applies the deployment-wide creation brake.
func (l *Limiter) CheckGlobal(ctx context.Context) (Result, error) {
	if !l.enabled {
		return Result{Allowed: true}, nil
	}
	allowed, retry, err := l.store.Allow(ctx,
		store.RateLimitKey("global", "create"), GlobalCreatePolicy.Interval(), GlobalCreatePolicy.Burst)
	if err != nil {
		return Result{Allowed: true}, err
	}
	return Result{Allowed: allowed, RetryAfter: retry}, nil
}

// Identity exposes the hashed client identifier for quota accounting.
func (l *Limiter) Identity(r *http.Request) string {
	return Identity(r, l.trusted, l.pepper)
}

// ApplyOverrides replaces the built-in allowances for the actions named in the
// map. Unknown action names are reported rather than ignored, because a typo
// in a deployment's configuration otherwise looks exactly like a limit that
// silently never took effect.
func (l *Limiter) ApplyOverrides(overrides map[string]Policy) []string {
	var unknown []string
	for name, policy := range overrides {
		action := Action(name)
		if _, ok := l.policies[action]; !ok {
			unknown = append(unknown, name)
			continue
		}
		l.policies[action] = policy
	}
	return unknown
}

// Policies returns the effective allowances, for logging at startup.
func (l *Limiter) Policies() map[Action]Policy {
	out := make(map[Action]Policy, len(l.policies))
	for k, v := range l.policies {
		out[k] = v
	}
	return out
}
