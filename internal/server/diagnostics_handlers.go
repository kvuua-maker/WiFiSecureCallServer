package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/diagnostics"
)

const maxDiagnosticBatch = 200

type diagnosticsLogRequest struct {
	Device  string               `json:"device"`
	Records []diagnostics.Record `json:"records"`
}

// diagnosticsLog accepts a batch from a device.
//
// Batches are capped and bodies are size limited: this endpoint is reachable by
// any signed-in installation, so it must not become a way to fill the disk.
func (s *Server) diagnosticsLog(w http.ResponseWriter, r *http.Request) {
	if s.diagnostics == nil {
		writeError(w, http.StatusServiceUnavailable, "diagnostics unavailable")
		return
	}
	body := http.MaxBytesReader(w, r.Body, 256<<10)
	var request diagnosticsLogRequest
	if err := json.NewDecoder(body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid diagnostics batch")
		return
	}
	if len(request.Records) == 0 || len(request.Records) > maxDiagnosticBatch {
		writeError(w, http.StatusBadRequest, "records must be between 1 and 200")
		return
	}
	device := strings.TrimSpace(request.Device)
	// Pre-sign-in batches carry only the device id. That is deliberate: the launch
	// sequence is exactly where failures happen, and it happens before a token
	// exists. The id must look like an installation id, and a device may not post
	// more than a batch per second.
	if device == "" || len(device) > 64 {
		writeError(w, http.StatusBadRequest, "device is required")
		return
	}
	if !s.diagnosticsAllow(device) {
		writeError(w, http.StatusTooManyRequests, "too many diagnostics batches")
		return
	}
	now := time.Now().UTC()
	for i := range request.Records {
		request.Records[i].Device = device
		if request.Records[i].Timestamp.IsZero() {
			request.Records[i].Timestamp = now
		}
	}
	if err := s.diagnostics.Append(request.Records); err != nil {
		writeError(w, http.StatusInternalServerError, "diagnostics write failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": len(request.Records)})
}

// diagnosticsRead returns stored records, oldest first, with optional filters.
func (s *Server) diagnosticsRead(w http.ResponseWriter, r *http.Request) {
	if s.diagnostics == nil {
		writeError(w, http.StatusServiceUnavailable, "diagnostics unavailable")
		return
	}
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	records, err := s.diagnostics.Read(diagnostics.Filter{
		Device:   query.Get("device"),
		Category: strings.ToUpper(query.Get("category")),
		Status:   query.Get("status"),
		Limit:    limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "diagnostics read failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(records),
		"summary": diagnostics.Summary(records),
		"records": records,
	})
}

// diagnosticsAllow is a coarse per-device rate limit: one batch per second, with a
// small burst window. It exists so an unsigned endpoint cannot be used to fill the
// disk, not to police honest clients.
func (s *Server) diagnosticsAllow(device string) bool {
	s.diagnosticsRateMu.Lock()
	defer s.diagnosticsRateMu.Unlock()
	now := time.Now()
	if s.diagnosticsRate == nil {
		s.diagnosticsRate = map[string]time.Time{}
	}
	if last, ok := s.diagnosticsRate[device]; ok && now.Sub(last) < time.Second {
		return false
	}
	s.diagnosticsRate[device] = now
	if len(s.diagnosticsRate) > 4096 {
		for key, at := range s.diagnosticsRate {
			if now.Sub(at) > time.Minute {
				delete(s.diagnosticsRate, key)
			}
		}
	}
	return true
}
