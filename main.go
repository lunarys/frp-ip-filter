package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/lunarys/frp-ip-filter/internal/allowlist"
	"github.com/lunarys/frp-ip-filter/internal/auth"
	"github.com/lunarys/frp-ip-filter/internal/config"
	"github.com/lunarys/frp-ip-filter/internal/server"
	"github.com/lunarys/frp-ip-filter/internal/tlscert"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	log.Printf("Loaded auth config: %d IP token(s), %d login(s)", len(cfg.Auth.IPTokens), len(cfg.Auth.Logins))

	list, err := allowlist.New(cfg.Allowlist.Path, cfg.Allowlist.MaxIPs, cfg.Allowlist.IPTTL, cfg.Allowlist.PrefixTTL)
	if err != nil {
		log.Fatalf("load allowlist: %v", err)
	}

	srv := server.New(
		list,
		auth.New(cfg.Auth.IPTokens, cfg.Auth.Logins),
		server.Logging{AccessLog: cfg.Logging.AccessLog, FrpDebug: cfg.Logging.FrpDebug},
	)

	publicSrv := &http.Server{
		Addr:              cfg.Server.PublicAddr,
		Handler:           srv.PublicHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if cfg.Server.TLSEnabled() {
		cert, err := tlscert.New(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			log.Fatalf("load TLS cert: %v", err)
		}
		publicSrv.TLSConfig.GetCertificate = cert.GetCertificate
	}

	privateSrv := &http.Server{
		Addr:              cfg.Server.PrivateAddr,
		Handler:           srv.PrivateHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		if cfg.Server.TLSEnabled() {
			log.Printf("Starting public server on %s (TLS enabled)", cfg.Server.PublicAddr)
			// Empty paths: publicSrv.TLSConfig.GetCertificate is already set, so
			// ListenAndServeTLS uses that instead of loading a static cert itself.
			errCh <- publicSrv.ListenAndServeTLS("", "")
			return
		}
		log.Printf("Starting public server on %s (TLS disabled)", cfg.Server.PublicAddr)
		errCh <- publicSrv.ListenAndServe()
	}()

	go func() {
		log.Printf("Starting private server on %s", cfg.Server.PrivateAddr)
		errCh <- privateSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server error: %v", err)
		}
	case <-ctx.Done():
		log.Println("Shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, s := range []*http.Server{publicSrv, privateSrv} {
		wg.Go(func() {
			if err := s.Shutdown(shutdownCtx); err != nil {
				log.Printf("shutdown error on %s: %v", s.Addr, err)
			}
		})
	}
	wg.Wait()

	log.Println("Server stopped")
}
