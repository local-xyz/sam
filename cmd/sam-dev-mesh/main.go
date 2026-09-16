//go:build sam_debug

// sam-dev-mesh runs the real SAM control plane and router for an isolated
// development mesh. Only its public enrollment URL and join token go to devices.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/google/sam/internal/standalone"
)

func run() error {
	dir := flag.String("data-dir", ".sam-dev-mesh", "Host-only issuer, router and database directory")
	bind := flag.String("listen", "127.0.0.1:18080", "HTTP and libp2p WebSocket listener")
	external := flag.String("external-url", "http://10.0.2.2:18080", "URL reachable by enrolled devices")
	output := flag.String("config-out", "device-config.json", "Private enrollment configuration output")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server, err := standalone.New(standalone.Options{BindAddress: *bind, ExternalURL: *external, DataDir: *dir})
	if err != nil {
		return err
	}
	if err = server.Start(ctx); err != nil {
		return err
	}
	defer server.Close()
	data, err := json.MarshalIndent(map[string]string{"bootstrapUrl": *external, "joinToken": server.JoinToken()}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(*output), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(*output, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err = os.Chmod(*output, 0600); err != nil {
		return err
	}
	fmt.Printf("Development mesh ready at %s; enrollment config: %s\n", server.Addr(), *output)
	<-ctx.Done()
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
