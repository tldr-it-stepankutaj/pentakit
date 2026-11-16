package services

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestBannerDeadline(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"zero timeout falls back to the cap", 0, maxBannerWait},
		{"negative timeout falls back to the cap", -1, maxBannerWait},
		{"long timeout (e.g. the 30s CLI default) is capped", 30 * time.Second, maxBannerWait},
		{"short, explicit timeout is honored as-is", 500 * time.Millisecond, 500 * time.Millisecond},
		{"timeout exactly at the cap is unchanged", maxBannerWait, maxBannerWait},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bannerDeadline(tc.timeout); got != tc.want {
				t.Errorf("bannerDeadline(%v) = %v, want %v", tc.timeout, got, tc.want)
			}
		})
	}
}

// startSilentServer starts a TCP server that accepts connections but never
// writes anything — the PostgreSQL wire-protocol situation that originally
// caused detectService to block for the full, 30s-by-default operation
// timeout on a single port.
func startSilentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open (so detectService's probes land on
			// a live-but-silent peer) until the test closes the listener.
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						_ = conn.Close()
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startBannerServer starts a TCP server that sends `banner` immediately on
// every accepted connection, like a real SSH/FTP/SMTP service would.
func startBannerServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(banner))
		}
	}()
	return ln.Addr().String()
}

// Regression test for the 30s-per-silent-port slowdown: detectService
// against a connectable-but-silent service must return in roughly
// maxBannerWait (a few seconds), not in the much longer operation timeout
// that's used for the connect phase.
func TestDetectService_SilentServiceReturnsQuickly(t *testing.T) {
	addr := startSilentServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	// A long operation timeout, matching the CLI's real 30s default — the
	// whole point of the fix is that detectService must not actually wait
	// anywhere near this long for a silent service.
	const longTimeout = 30 * time.Second

	start := time.Now()
	result := detectService(context.Background(), host, port, longTimeout, true)
	elapsed := time.Since(start)

	if result == nil {
		t.Fatal("expected a result (the port is open), got nil")
	}
	// Two banner-wait-capped phases total: the initial read, plus the probe
	// sequence (which now shares ONE deadline across all 3 probes rather
	// than resetting a full wait per probe). Generous slack included,
	// still far below longTimeout.
	if budget := 3 * maxBannerWait; elapsed > budget { // 2x expected + 1x slack
		t.Errorf("detectService took %v against a silent service, want under %v (longTimeout was %v)",
			elapsed, budget, longTimeout)
	}
}

// An explicit short timeout must still be honored (not stretched to
// maxBannerWait) when it's already shorter than the cap.
func TestDetectService_HonorsShortExplicitTimeout(t *testing.T) {
	addr := startSilentServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	const shortTimeout = 300 * time.Millisecond

	start := time.Now()
	detectService(context.Background(), host, port, shortTimeout, true)
	elapsed := time.Since(start)

	if budget := 3 * shortTimeout; elapsed > budget { // 2x expected (initial read + shared probe budget) + 1x slack
		t.Errorf("detectService took %v with a %v timeout, want under %v", elapsed, shortTimeout, budget)
	}
}

// A service that sends its banner immediately must be identified without
// waiting for any timeout at all.
func TestDetectService_BannerServiceReturnsImmediately(t *testing.T) {
	addr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6\r\n")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	start := time.Now()
	result := detectService(context.Background(), host, port, 30*time.Second, true)
	elapsed := time.Since(start)

	if result == nil || result.Service != "SSH" {
		t.Fatalf("expected service SSH to be identified, got %+v", result)
	}
	if elapsed > time.Second {
		t.Errorf("detectService took %v for an immediate banner, want near-instant", elapsed)
	}
}
