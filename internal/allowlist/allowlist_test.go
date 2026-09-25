package allowlist

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAddIPCapacity(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "allowlist.json"), 2, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")
	ip3 := netip.MustParseAddr("10.0.0.3")

	if err := a.AddIP(ip1); err != nil {
		t.Fatalf("AddIP(ip1): %v", err)
	}
	if err := a.AddIP(ip2); err != nil {
		t.Fatalf("AddIP(ip2): %v", err)
	}
	if err := a.AddIP(ip3); !errors.Is(err, ErrCapacityFull) {
		t.Fatalf("AddIP(ip3): got %v, want ErrCapacityFull", err)
	}

	// Re-adding an already-present IP must not be rejected by the cap.
	if err := a.AddIP(ip1); err != nil {
		t.Fatalf("AddIP(ip1) again: %v", err)
	}
}

func TestAddIPExpirySweepFreesCapacity(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "allowlist.json"), 1, time.Millisecond, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")

	if err := a.AddIP(ip1); err != nil {
		t.Fatalf("AddIP(ip1): %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	// ip1 has expired, so adding ip2 should sweep it and succeed under the cap.
	if err := a.AddIP(ip2); err != nil {
		t.Fatalf("AddIP(ip2) after ip1 expiry: %v", err)
	}
	if isAllowed(a, ip1) {
		t.Fatal("ip1 should have expired")
	}
	if !isAllowed(a, ip2) {
		t.Fatal("ip2 should be allowed")
	}
}

func TestIsAllowedExpiry(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "allowlist.json"), 10, time.Millisecond, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("10.0.0.1")
	if err := a.AddIP(ip); err != nil {
		t.Fatal(err)
	}
	if !isAllowed(a, ip) {
		t.Fatal("ip should be allowed immediately after add")
	}

	time.Sleep(5 * time.Millisecond)

	if isAllowed(a, ip) {
		t.Fatal("ip should no longer be allowed after TTL expiry")
	}
}

func TestAddPrefixUpsert(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "allowlist.json"), 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	p1 := netip.MustParsePrefix("2001:db8:1::/64")
	p2 := netip.MustParsePrefix("2001:db8:2::/64")

	if err := a.AddPrefix("alice", p1); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPrefix("alice", p2); err != nil {
		t.Fatal(err)
	}

	if len(a.prefixes) != 1 {
		t.Fatalf("expected 1 prefix entry (upsert), got %d", len(a.prefixes))
	}

	inP1 := netip.MustParseAddr("2001:db8:1::1")
	inP2 := netip.MustParseAddr("2001:db8:2::1")

	if isAllowed(a, inP1) {
		t.Fatal("old prefix should have been replaced")
	}
	if !isAllowed(a, inP2) {
		t.Fatal("new prefix should be allowed")
	}
}

func TestIsAllowedReturnsLoginOnlyForPrefixMatch(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "allowlist.json"), 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("10.0.0.1")
	if err := a.AddIP(ip); err != nil {
		t.Fatal(err)
	}
	if allowed, login := a.IsAllowed(ip); !allowed || login != "" {
		t.Fatalf("directly registered IP: got allowed=%v login=%q, want allowed=true login=\"\"", allowed, login)
	}

	prefix := netip.MustParsePrefix("2001:db8::/32")
	if err := a.AddPrefix("dave", prefix); err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("2001:db8::1")
	if allowed, login := a.IsAllowed(addr); !allowed || login != "dave" {
		t.Fatalf("prefix match: got allowed=%v login=%q, want allowed=true login=%q", allowed, login, "dave")
	}
}

func TestPrefixExpiry(t *testing.T) {
	a, err := New(filepath.Join(t.TempDir(), "allowlist.json"), 10, time.Hour, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	p := netip.MustParsePrefix("2001:db8::/32")
	if err := a.AddPrefix("bob", p); err != nil {
		t.Fatal(err)
	}

	addr := netip.MustParseAddr("2001:db8::1")
	if !isAllowed(a, addr) {
		t.Fatal("should be allowed immediately after add")
	}

	time.Sleep(5 * time.Millisecond)

	if isAllowed(a, addr) {
		t.Fatal("prefix should have expired")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")

	a, err := New(path, 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("192.168.1.1")
	prefix := netip.MustParsePrefix("2001:db8::/32")

	if err := a.AddIP(ip); err != nil {
		t.Fatal(err)
	}
	if err := a.AddPrefix("carol", prefix); err != nil {
		t.Fatal(err)
	}

	reloaded, err := New(path, 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if !isAllowed(reloaded, ip) {
		t.Fatal("reloaded allowlist should still allow the persisted IP")
	}
	if !isAllowed(reloaded, netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("reloaded allowlist should still allow the persisted prefix")
	}
}

func TestPersistenceSkipsExpiredOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")

	a, err := New(path, 10, time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	ip := netip.MustParseAddr("192.168.1.1")
	if err := a.AddIP(ip); err != nil {
		t.Fatal(err)
	}

	time.Sleep(5 * time.Millisecond)

	reloaded, err := New(path, 10, time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	if isAllowed(reloaded, ip) {
		t.Fatal("expired entry should not survive reload")
	}
}

func TestNewAllowlistCorruptFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.json")

	if err := writeFile(path, "not valid json"); err != nil {
		t.Fatal(err)
	}

	a, err := New(path, 10, time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("New should tolerate a corrupt file, got error: %v", err)
	}
	if len(a.ips) != 0 || len(a.prefixes) != 0 {
		t.Fatal("expected empty allowlist after corrupt file")
	}
}

func writeFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o644)
}

func isAllowed(a *List, ip netip.Addr) bool {
	allowed, _ := a.IsAllowed(ip)
	return allowed
}
