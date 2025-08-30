package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/tldr-it-stepankutaj/pentakit/internal/app"
)

// Module implements the basic recon module metadata.
type Module struct{}

func New() Module { return Module{} }

func (Module) Name() string        { return "recon" }
func (Module) Description() string { return "Basic TCP connect probe for a target" }

// RunConfig configures the recon run.
type RunConfig struct {
	Target  string
	Ports   []int
	Timeout time.Duration
}

// Result represents a single open port finding.
type Result struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Run executes a concurrent TCP connect probe on the given target.
func Run(ctx app.Context, cfg RunConfig) error {
	if cfg.Target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []int{80, 443}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	results, err := probe(ctx.Ctx, cfg.Target, cfg.Ports, cfg.Timeout, 200)
	if err != nil {
		return err
	}

	// Sort results for stable output.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// For MVP, print to stdout. Later: write JSONL to workspace findings.
	for _, r := range results {
		fmt.Printf("%s:%d open\n", r.Host, r.Port)
	}
	if len(results) == 0 {
		fmt.Println("No open ports found in provided set.")
	}
	return nil
}

// probe performs concurrent TCP connect attempts to the given ports.
func probe(ctx context.Context, host string, ports []int, dialTimeout time.Duration, concurrency int) ([]Result, error) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	out := make([]Result, 0, 8)

	dialer := &net.Dialer{Timeout: dialTimeout}

	for _, p := range ports {
		p := p
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			addr := fmt.Sprintf("%s:%d", host, p)
			cctx, cancel := context.WithTimeout(ctx, dialTimeout)
			conn, err := dialer.DialContext(cctx, "tcp", addr)
			cancel()
			if err == nil {
				_ = conn.Close()
				mu.Lock()
				out = append(out, Result{Host: host, Port: p})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out, nil
}
