package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"raven/internal/witness"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		if err := keygen(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	fs := flag.NewFlagSet("raven-witness", flag.ExitOnError)
	configPath := fs.String("config", "", "path to the local witness YAML configuration")
	_ = fs.Parse(os.Args[1:])
	if *configPath == "" {
		log.Fatal("-config is required")
	}
	cfg, err := witness.LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	store, err := witness.OpenStore(cfg.DatabasePath, cfg.StreamID, cfg.GenesisHash)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	api, err := witness.NewServer(store, cfg.StreamID, cfg.ProducerToken, cfg.AdminToken, cfg.Signer)
	if err != nil {
		log.Fatal(err)
	}
	var anchorer *witness.Anchorer
	if cfg.Anchor != nil {
		anchorer, err = witness.StartAnchorer(context.Background(), store, cfg.StreamID, cfg.GenesisHash, *cfg.Anchor)
		if err != nil {
			log.Fatalf("initialize pinned Ethereum anchor: %v", err)
		}
		defer anchorer.Close()
	}
	auditor := witness.NewLedgerAuditor(store, anchorer, cfg.Signer)
	defer auditor.Stop()
	api.SetLedgerAuditor(auditor)
	server := &http.Server{
		Addr: cfg.ListenAddress, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if anchorer != nil {
		anchorer.Start(ctx, time.Second)
	}
	auditor.Start(ctx, 15*time.Minute)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("raven-witness listening on %s", cfg.ListenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("raven-witness keygen", flag.ContinueOnError)
	privatePath := fs.String("private-key", "", "destination for base64 Ed25519 private key (0600)")
	publicPath := fs.String("public-key", "", "destination for base64 Ed25519 public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" {
		return fmt.Errorf("usage: raven-witness keygen -private-key PATH -public-key PATH")
	}
	return witness.GenerateReceiptKey(*privatePath, *publicPath)
}
