// Command sipgateway runs the SIP front door of WiFi Secure Call.
//
// It is a separate process from the HTTP signalling server because it needs its
// own ports (5060 UDP, 5061 TLS) and its own failure domain: a SIP restart must
// not interrupt the account and notification APIs.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/sipgw"
)

func main() {
	logger := newLogger()
	slog.SetDefault(logger)

	cfg, err := sipgw.LoadConfig(os.Getenv)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	gateway, err := sipgw.New(cfg, logger)
	if err != nil {
		logger.Error("gateway setup failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	httpAddr := os.Getenv("SIPGW_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = "127.0.0.1:8791"
	}
	statusServer := &http.Server{
		Addr:              httpAddr,
		Handler:           routes(gateway, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	var ready atomic.Bool
	go func() {
		logger.Info("status endpoint listening", "address", httpAddr)
		if err := statusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("status endpoint stopped", "error", err)
		}
	}()

	if cfg.Trunk.Enabled() {
		logger.Info("upstream trunk configured", "address", cfg.Trunk.Address(), "transport", cfg.Trunk.Transport)
	} else {
		logger.Warn("no upstream trunk: only calls between registered devices will connect")
	}
	if !cfg.MediaRelayEnabled() {
		logger.Warn("media relay disabled: SDP is passed through unchanged and the device must be reachable directly")
	}

	ready.Store(true)
	started := time.Now()
	err = gateway.Start(ctx)
	ready.Store(false)
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = statusServer.Shutdown(shutdown)
	if cerr := gateway.Close(); cerr != nil {
		logger.Warn("gateway close", "error", cerr)
	}
	if err != nil {
		logger.Error("gateway stopped", "error", err, "uptime", time.Since(started).String())
		os.Exit(1)
	}
	logger.Info("gateway stopped", "uptime", time.Since(started).String())
}

func routes(gateway *sipgw.Gateway, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"stats":         gateway.Stats(),
			"registrations": gateway.Registrar().Snapshot(time.Now()),
		})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		stats := gateway.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP wsc_sip_registrations_total Successful REGISTER transactions.\n")
		fmt.Fprintf(w, "# TYPE wsc_sip_registrations_total counter\n")
		fmt.Fprintf(w, "wsc_sip_registrations_total %d\n", stats.Registrations)
		fmt.Fprintf(w, "# HELP wsc_sip_registration_failures_total Rejected REGISTER transactions.\n")
		fmt.Fprintf(w, "# TYPE wsc_sip_registration_failures_total counter\n")
		fmt.Fprintf(w, "wsc_sip_registration_failures_total %d\n", stats.RegistrationFails)
		fmt.Fprintf(w, "# HELP wsc_sip_invites_total INVITEs by direction.\n")
		fmt.Fprintf(w, "# TYPE wsc_sip_invites_total counter\n")
		fmt.Fprintf(w, "wsc_sip_invites_total{direction=\"outbound\"} %d\n", stats.InvitesOut)
		fmt.Fprintf(w, "wsc_sip_invites_total{direction=\"inbound\"} %d\n", stats.InvitesIn)
		fmt.Fprintf(w, "# HELP wsc_sip_invites_rejected_total INVITEs refused by routing or auth.\n")
		fmt.Fprintf(w, "# TYPE wsc_sip_invites_rejected_total counter\n")
		fmt.Fprintf(w, "wsc_sip_invites_rejected_total %d\n", stats.InvitesRejected)
		fmt.Fprintf(w, "# HELP wsc_sip_active_calls Calls currently holding a relay.\n")
		fmt.Fprintf(w, "# TYPE wsc_sip_active_calls gauge\n")
		fmt.Fprintf(w, "wsc_sip_active_calls %d\n", stats.ActiveCalls)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Debug("status response failed", "error", err)
	}
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if raw := os.Getenv("LOG_LEVEL"); raw != "" {
		if err := level.UnmarshalText([]byte(raw)); err != nil {
			level = slog.LevelInfo
		}
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
