package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"detector/internal/config"
	"detector/internal/db"
	"detector/internal/detect"
	"detector/internal/handler"
	"detector/internal/logger"
	"detector/internal/server"
)

// Set via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to config file (toml)")
	flag.StringVar(&cfgPath, "c", "", "path to config file (shorthand for -config)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if cfgPath == "" {
		flag.Usage()
		return errors.New("config file is required: -config <file> or -c <file>")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	loc, _ := cfg.Location()
	level, _ := cfg.SlogLevel()

	log, closer, err := logger.New(logger.Options{
		Dir:    cfg.Log.Dir,
		Prefix: cfg.Log.Prefix,
		Level:  level,
		Loc:    loc,
		Stdout: cfg.Log.Stdout,
	})
	if err != nil {
		return err
	}
	defer closer.Close()
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, cfg.Database)
	if err != nil {
		log.Error("database open failed", "err", err)
		return err
	}
	defer database.Close()

	dm := detect.NewManager(database, log, cfg.Detect)
	detectDone := make(chan struct{})
	go func() {
		defer close(detectDone)
		dm.Run(ctx)
	}()

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Common.APIPort),
		Handler:           server.NewHandler(handler.New(database, loc, version, dm), log),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server started",
			"version", version,
			"addr", srv.Addr,
			"timeZone", loc.String(),
			"logLevel", level.String(),
			"db", cfg.Database.FilePath,
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			log.Error("server failed", "err", err)
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stop() // also stops detectors when the server failed on its own
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown failed", "err", err)
		return err
	}
	select {
	case <-detectDone:
	case <-shutdownCtx.Done():
		log.Warn("detectors did not stop in time")
	}
	log.Info("server stopped")
	return nil
}
