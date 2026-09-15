package session

import (
	"strings"
	"testing"
)

func ptr(n int) *int { return &n }

// The relay's five statuses are the five outcomes. AUTH.md fixes one status per
// state, so reading the status alone has to be enough.
func TestClassifyReadsTheRelaysFiveStatuses(t *testing.T) {
	cases := []struct {
		status int
		code   string
		want   step
	}{
		{200, "", stepIssued},
		{428, "authorization_pending", stepPending},
		{429, "slow_down", stepSlowDown},
		{403, "access_denied", stepDenied},
		{410, "expired_token", stepGone},
	}
	for _, c := range cases {
		if got := classify(c.status, c.code); got != c.want {
			t.Errorf("classify(%d, %q) = %v, want %v", c.status, c.code, got, c.want)
		}
	}
}

// A proxy that rewrote the status, or a relay older than this build, still
// speaks RFC 8628's vocabulary in the body.
func TestClassifyFallsBackToTheErrorCode(t *testing.T) {
	if got := classify(400, "authorization_pending"); got != stepPending {
		t.Errorf("400 authorization_pending = %v, want pending", got)
	}
	if got := classify(400, "expired_token"); got != stepGone {
		t.Errorf("400 expired_token = %v, want gone", got)
	}
	if got := classify(500, "storage_error"); got != stepFailed {
		t.Errorf("500 storage_error = %v, want failed", got)
	}
}

// The number the relay sends is the number that is used. It puts the new
// interval in the body and in Retry-After for exactly this reason.
func TestNextIntervalHonoursTheRelaysNumber(t *testing.T) {
	if got := nextInterval(ptr(10), 0, 5); got != 10 {
		t.Errorf("body 10 from 5 = %d, want 10", got)
	}
	if got := nextInterval(ptr(15), 0, 10); got != 15 {
		t.Errorf("body 15 from 10 = %d, want 15", got)
	}
	// The header is the fallback when the body did not carry one.
	if got := nextInterval(nil, 20, 10); got != 20 {
		t.Errorf("header 20 from 10 = %d, want 20", got)
	}
	// The body wins over the header when they disagree: the header is an HTTP
	// convention and the body is this relay's contract.
	if got := nextInterval(ptr(10), 45, 5); got != 10 {
		t.Errorf("body 10 with header 45 = %d, want 10", got)
	}
}

// With no number at all, step the way the relay does, and stay inside its own
// bounds either way.
func TestNextIntervalWithoutANumberStepsAndIsBounded(t *testing.T) {
	if got := nextInterval(nil, 0, 5); got != 10 {
		t.Errorf("no number from 5 = %d, want 10", got)
	}
	// Never below what is already in force: a smaller number only earns
	// another slow_down.
	if got := nextInterval(ptr(2), 0, 10); got != 10 {
		t.Errorf("body 2 from 10 = %d, want 10", got)
	}
	// Never above the relay's ceiling: a client that misbehaved once should
	// not end up polling once an hour.
	if got := nextInterval(ptr(3600), 0, 55); got != maxInterval {
		t.Errorf("body 3600 = %d, want %d", got, maxInterval)
	}
}

// A 410 is also the answer for an unknown code and for one already claimed, so
// the words a person sees must not be "your code expired".
func TestTheGoneDetailDoesNotSayExpired(t *testing.T) {
	if want := "no longer valid"; !strings.Contains(goneDetail, want) {
		t.Errorf("the 410 detail %q does not say %q", goneDetail, want)
	}
	if strings.Contains(goneDetail, "expired") {
		t.Errorf("the 410 detail says 'expired', which is misleading for a typo: %q", goneDetail)
	}
}
