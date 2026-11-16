package bruteforce

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer starts a minimal SSH server on 127.0.0.1 that accepts
// exactly one username/password pair and rejects everything else. It
// returns the listener's address; callers should close the returned
// net.Listener (via t.Cleanup) to shut it down.
func startTestSSHServer(t *testing.T, validUser, validPass string) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("failed to create host key signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if c.User() == validUser && string(password) == validPass {
				return nil, nil
			}
			return nil, &ssh.ServerAuthError{}
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed, test is done
			}
			go func() {
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					_ = conn.Close()
					return // failed handshake/auth; nothing more to do
				}
				defer func() { _ = sshConn.Close() }()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					_ = newChan.Reject(ssh.Prohibited, "no channels available in this test server")
				}
			}()
		}
	}()

	return listener.Addr().String()
}

func TestTestSSH_CorrectCredentialsSucceed(t *testing.T) {
	addr := startTestSSHServer(t, "admin", "s3cret")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split test server address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	cfg := &RunConfig{Timeout: 2 * time.Second}
	ok, details := testSSH(context.Background(), host, port, "admin", "s3cret", cfg)
	if !ok {
		t.Fatalf("expected success with correct credentials, got failure (details: %q)", details)
	}
}

func TestTestSSH_WrongPasswordFails(t *testing.T) {
	addr := startTestSSHServer(t, "admin", "s3cret")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split test server address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	cfg := &RunConfig{Timeout: 2 * time.Second}
	ok, _ := testSSH(context.Background(), host, port, "admin", "wrong-password", cfg)
	if ok {
		t.Fatal("expected failure with an incorrect password, got success")
	}
}

func TestTestSSH_NothingListeningFails(t *testing.T) {
	cfg := &RunConfig{Timeout: 500 * time.Millisecond}
	// Port 1 is reserved and nothing should ever be listening there in a
	// test environment; this exercises the "connection refused" path.
	ok, _ := testSSH(context.Background(), "127.0.0.1", 1, "admin", "s3cret", cfg)
	if ok {
		t.Fatal("expected failure when nothing is listening, got success")
	}
}
