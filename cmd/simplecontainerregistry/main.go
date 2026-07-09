package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"simplecontainerregistry/internal/auth"
	"simplecontainerregistry/internal/config"
	"simplecontainerregistry/internal/db"
	"simplecontainerregistry/internal/domain"
	"simplecontainerregistry/internal/httpserver"
	"simplecontainerregistry/internal/storage"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := storage.EnsureRoot(cfg.Storage.RootDirectory); err != nil {
		logger.Error("failed to initialize storage root", "error", err)
		os.Exit(1)
	}

	store, err := db.Open(ctx, cfg.Database.DSN)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	if err := store.InitSchema(ctx); err != nil {
		logger.Error("failed to initialize database schema", "error", err)
		os.Exit(1)
	}

	if err := store.EnsureActiveSigningKey(ctx); err != nil {
		logger.Error("failed to initialize signing key", "error", err)
		os.Exit(1)
	}

	if cfg.Bootstrap.AdminUsername != "" || cfg.Bootstrap.AdminPassword != "" {
		if err := auth.BootstrapAdmin(ctx, store, cfg.Bootstrap.AdminUsername, cfg.Bootstrap.AdminPassword, time.Now().UTC()); err != nil {
			logger.Error("failed to bootstrap admin", "error", err)
			os.Exit(1)
		}
	}

	server := httpserver.New(httpserver.Options{
		Config: cfg,
		Store:  store,
		Logger: logger,
	})
	registryFS, err := storage.NewFilesystem(cfg.Storage.RootDirectory)
	if err != nil {
		logger.Error("failed to initialize registry filesystem", "error", err)
		os.Exit(1)
	}
	go runGarbageCollector(ctx, logger, store, registryFS, domain.GCSettings{
		Enabled:  cfg.Storage.GC,
		Delay:    cfg.Storage.GCDelay.Std(),
		Interval: cfg.Storage.GCInterval.Std(),
	})

	httpServer := &http.Server{
		Addr:              cfg.HTTP.ListenAddress(),
		Handler:           server,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("starting server", "address", httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown failed", "error", err)
		os.Exit(1)
	}
}

func runGarbageCollector(ctx context.Context, logger *slog.Logger, store *db.Store, registryFS storage.Filesystem, fallback domain.GCSettings) {
	interval := fallback.Interval
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			settings, err := store.GCSettings(ctx, fallback)
			if err != nil {
				logger.Error("failed to load gc settings", "error", err)
			} else {
				if settings.Enabled {
					result, err := registryFS.CollectGarbage(time.Now().UTC().Add(-settings.Delay))
					if err != nil {
						logger.Error("garbage collection failed", "error", err)
					} else if result.DeletedManifests > 0 {
						logger.Info("garbage collection completed", "deleted_manifests", result.DeletedManifests)
					}
				}
				if settings.Interval > 0 {
					interval = settings.Interval
				}
			}
			timer.Reset(interval)
		}
	}
}
