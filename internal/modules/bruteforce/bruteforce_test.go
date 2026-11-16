package bruteforce

import (
	"context"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// testWorkspace is a minimal app.WorkspaceHandle backed by a temp directory,
// so Run's "persist findings" side effect (writeJSONL) has somewhere real to
// write instead of panicking on a nil WorkspaceHandle.
type testWorkspace struct{ root string }

func (w testWorkspace) Path(parts ...string) string {
	return filepath.Join(append([]string{w.root}, parts...)...)
}

// Regression test for a data race around StopOnSuccess: the success branch
// used to write `stopped = true` from inside a worker goroutine while the
// dispatch loop read/wrote that same plain bool from the main goroutine with
// no synchronization, and nothing guarded close(stopChan) against being
// called twice when two workers succeeded concurrently (a second close on an
// already-closed channel panics). Run with -race; a high Concurrency and a
// target that accepts every credential makes many workers "succeed" in the
// same instant, which is exactly the scenario that used to race/panic.
func TestRun_StopOnSuccess_NoRaceNoPanic(t *testing.T) {
	srv := httptest.NewServer(nil)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("failed to parse test server port: %v", err)
	}

	users := make([]string, 50)
	passwords := make([]string, 50)
	for i := range users {
		users[i] = "user" + strconv.Itoa(i)
		passwords[i] = "pass" + strconv.Itoa(i)
	}

	cfg := RunConfig{
		Target:        u.Hostname(),
		Port:          port,
		Protocol:      "http",
		UserList:      users,
		PassList:      passwords,
		Concurrency:   25,
		Timeout:       2 * time.Second,
		StopOnSuccess: true,
		// httptest.NewServer(nil) serves 404 for everything, which still
		// satisfies the default "any 2xx-ish/non-401/403 response" rule in
		// testHTTP only for 2xx — so force success via HTTPSuccessCode
		// matching the 404 every single attempt actually gets, guaranteeing
		// many concurrent "successes" instead of relying on timing.
		HTTPSuccessCode: 404,
	}

	ctx := app.Context{Ctx: context.Background(), Now: time.Now(), Workspace: testWorkspace{root: t.TempDir()}}

	results, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one recorded success")
	}
}
