package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/calls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/config"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devices"
	appserver "github.com/kvuua-maker/wifi-secure-call-server/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	deviceStore, err := devices.Open(cfg.StatePath)
	if err != nil {
		slog.Error("device state failed", "error", err)
		os.Exit(1)
	}
	var push apns.Sender = apns.Disabled{}
	if cfg.APNSEnabled {
		client, e := apns.New(
			cfg.APNSTeamID, cfg.APNSKeyID, cfg.APNSKeyPath,
			cfg.APNSTopicIOS, cfg.APNSTopicWatch,
			cfg.APNSTopicIOSVoIP, cfg.APNSTopicWatchVoIP,
		)
		if e != nil {
			slog.Error("APNs configuration failed", "error", e)
			os.Exit(1)
		}
		push = client
	}
	callStore := calls.New(cfg.RingTimeout, cfg.MediaGrace)
	server := appserver.New(cfg.TokenA, cfg.TokenB, callStore, deviceStore, push)
	httpServer := &http.Server{Addr: cfg.Address, Handler: server.Handler(), ReadHeaderTimeout: 5e9, IdleTimeout: 30e9, MaxHeaderBytes: 8192}
	slog.Info("wifi-secure-call listening", "address", cfg.Address, "apnsConfigured", push.Configured())
	if err = httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
