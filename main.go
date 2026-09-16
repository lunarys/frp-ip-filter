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
)

func main() {
	authCfg, err := loadAuthConfigFromEnv()
	if err != nil {
		log.Fatalf("load auth config: %v", err)
	}
	log.Printf("Loaded auth config: %d IP token(s), %d login(s)", len(authCfg.ipTokens), len(authCfg.logins))

	listCfg, err := loadAllowlistConfig()
	if err != nil {
		log.Fatalf("load allowlist config: %v", err)
	}

	list, err := newAllowlist(listCfg.path, listCfg.maxIPs, listCfg.ipTTL, listCfg.prefixTTL)
	if err != nil {
		log.Fatalf("load allowlist: %v", err)
	}

	loggingCfg, err := loadLoggingConfig()
	if err != nil {
		log.Fatalf("load logging config: %v", err)
	}

	srv := &server{allowlist: list, auth: authCfg, logging: loggingCfg, proxyFilters: newProxyFilters()}

	serverCfg, err := loadServerConfig()
	if err != nil {
		log.Fatalf("load server config: %v", err)
	}

	muxPrivate := http.NewServeMux()
	muxPublic := http.NewServeMux()

	muxPublic.HandleFunc("GET /unlock", srv.registerClient)
	muxPublic.HandleFunc("GET /dyndns", srv.registerClientPrefix)

	muxPrivate.HandleFunc("POST /frp-plugin", srv.frpPluginHandler)
	muxPrivate.HandleFunc("GET /healthz", srv.healthCheck)

	publicSrv := &http.Server{
		Addr:              serverCfg.publicAddr,
		Handler:           muxPublic,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if serverCfg.tlsEnabled() {
		cert, err := newReloadingCert(serverCfg.tlsCertFile, serverCfg.tlsKeyFile)
		if err != nil {
			log.Fatalf("load TLS cert: %v", err)
		}
		publicSrv.TLSConfig.GetCertificate = cert.GetCertificate
	}

	privateSrv := &http.Server{
		Addr:              serverCfg.privateAddr,
		Handler:           muxPrivate,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	go func() {
		if serverCfg.tlsEnabled() {
			log.Printf("Starting public server on %s (TLS enabled)", serverCfg.publicAddr)
			// Empty paths: publicSrv.TLSConfig.GetCertificate is already set, so
			// ListenAndServeTLS uses that instead of loading a static cert itself.
			errCh <- publicSrv.ListenAndServeTLS("", "")
			return
		}
		log.Printf("Starting public server on %s (TLS disabled)", serverCfg.publicAddr)
		errCh <- publicSrv.ListenAndServe()
	}()

	go func() {
		log.Printf("Starting private server on %s", serverCfg.privateAddr)
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
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if err := s.Shutdown(shutdownCtx); err != nil {
				log.Printf("shutdown error on %s: %v", s.Addr, err)
			}
		}(s)
	}
	wg.Wait()

	log.Println("Server stopped")
}
