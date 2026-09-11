package rpc

import "testing"

func TestErrorCodes(t *testing.T) {
	e := NewError(CodeNotFound, "port 3000 not found", "run `sonar list`")
	if e.Code != 1001 || e.Data.Code != "not_found" || e.Data.Hint == "" {
		t.Fatalf("%+v", e)
	}
}

func TestEveryRegistryCodeHasAName(t *testing.T) {
	for _, c := range []int{CodeInvalidParams, CodeInternal, CodeNotFound, CodeAmbiguous,
		CodePermission, CodeUnsupported, CodeBusy, CodeInvalidConfig, CodeAlreadyRunning,
		CodeTimeout, CodeInvalidSelector, CodeOutsideHome, CodeTargetNotListening,
		CodeShareLimitReached, CodeListenPortInUse, CodeNotSignedIn, CodeShareExpired,
		CodeRelayUnreachable, CodeShareBlocked,
		CodeSessionNotFound, CodeClaimConflict} {
		if CodeName(c) == "" {
			t.Fatalf("code %d has no data.code name", c)
		}
	}
	if CodeName(4242) != "internal" {
		t.Fatalf("unknown codes must fall back to internal, got %q", CodeName(4242))
	}
}

// The 1100 block is the share block (docs/SHARE.md in sonar-relay). The
// numbers are the wire contract, so they are pinned here, and the provider
// codes the old expose design reserved are gone rather than renamed.
func TestShareErrorCodes(t *testing.T) {
	want := map[int]string{
		1100: "target_not_listening",
		1107: "share_limit_reached",
		1108: "listen_port_in_use",
		1110: "not_signed_in",
		1111: "share_expired",
		1112: "relay_unreachable",
		1113: "share_blocked",
	}
	for code, name := range want {
		if got := CodeName(code); got != name {
			t.Errorf("CodeName(%d) = %q, want %q", code, got, name)
		}
	}
	for _, code := range []int{1101, 1102, 1103, 1104, 1105, 1106, 1109} {
		if got, ok := codeNames[code]; ok {
			t.Errorf("code %d is still registered as %q; the provider codes were deleted", code, got)
		}
	}
}

func TestErrorImplementsError(t *testing.T) {
	var err error = NewError(CodeTimeout, "timed out", "raise --timeout")
	if err.Error() != "timed out" {
		t.Fatalf("Error() = %q", err.Error())
	}
}
