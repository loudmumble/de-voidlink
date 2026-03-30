package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"de-voidlink/c2/internal/cadence"
	"de-voidlink/c2/internal/handler"
	"de-voidlink/c2/internal/server"
)

func main() {
	// CLI flags matching VoidLink C2 protocol
	bind := flag.String("bind", "127.0.0.1:8080", "Listen address")
	mode := flag.String("mode", "voidlink", `Traffic mode: "voidlink" or "ai-cadence"`)
	maxRuntime := flag.Int("max-runtime", 300, "Auto-shutdown after N seconds")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS")
	flag.Parse()

	// Validate traffic mode
	if *mode != cadence.ModeVoidLink && *mode != cadence.ModeAICadence {
		log.Fatalf("Invalid mode %q: must be %q or %q", *mode, cadence.ModeVoidLink, cadence.ModeAICadence)
	}

	cfg := server.Config{
		Bind:       *bind,
		MaxRuntime: *maxRuntime,
		Verbose:    *verbose,
		TLS:        *tlsEnabled,
	}

	// Initialize components
	store := server.NewSessionStore()
	cadenceMgr := cadence.NewManager(*mode)
	mux := http.NewServeMux()

	// Create server (needed for shutdown function reference)
	srv := server.New(cfg, mux, store)

	// Create handler with all dependencies
	h := handler.New(store, cadenceMgr, *verbose, *mode, srv.Shutdown)
	h.RegisterRoutes(mux)

	// Handle OS signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down", sig)
		srv.Shutdown()
	}()

	if *tlsEnabled {
		log.Println("WARNING: --tls flag accepted but TLS is not yet implemented; server will use plain HTTP")
	}

	log.Printf("Mode: %s | MaxRuntime: %ds | Verbose: %v | TLS: %v",
		*mode, *maxRuntime, *verbose, *tlsEnabled)

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped")
}
