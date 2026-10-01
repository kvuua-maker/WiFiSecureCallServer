package accountmedia

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gorilla/websocket"
)

const (
	legacyAudioPacketSize    = 674
	audioPacketSize          = legacyAudioPacketSize
	encryptedAudioPacketSize = 707
	controlPacketSize        = 34
	outboundCapacity         = 64
	maxViolations            = 5
)

type Validator interface {
	ValidateMedia(id, side, token string) bool
	RequiredMediaProtocol(id string) int
	MediaPeerJoined(id, side, epoch string) bool
	MediaPeerLeft(id, side, epoch string)
	IsAccepted(id string) bool
}

type Hub struct {
	validator Validator
	upgrader  websocket.Upgrader
	mu        sync.Mutex
	peers     map[string]map[string]*peer
}

type peer struct {
	conn                *websocket.Conn
	callID, side, epoch string
	protocolVersion     int
	outbound            chan []byte
	control             chan []byte
	done                chan struct{}
	closeOnce           sync.Once
	lastSequence        uint64
	hasSequence         bool
}

type connectionStats struct{ binaryMessages, validAudioPackets, invalidPackets, audioBytes, relayedPackets, relayFailures, peerMissingCount uint64 }

func New(validator Validator) *Hub {
	return &Hub{validator: validator, upgrader: websocket.Upgrader{HandshakeTimeout: 5 * time.Second, ReadBufferSize: 1024, WriteBufferSize: 1024, CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		return origin == "" || origin == "https://178.105.32.46"
	}}, peers: map[string]map[string]*peer{}}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, side := strings.ToLower(r.URL.Query().Get("callID")), r.URL.Query().Get("side")
	token, ok := strictBearer(r.Header.Get("Authorization"))
	if !ok || !h.validator.ValidateMedia(id, side, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	version := 1
	switch r.URL.Query().Get("protocolVersion") {
	case "", "1":
	case "2":
		version = 2
	default:
		http.Error(w, "unsupported media protocol", http.StatusUpgradeRequired)
		return
	}
	if h.validator.RequiredMediaProtocol(id) != version {
		http.Error(w, "unsupported media protocol", http.StatusUpgradeRequired)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	p := &peer{conn: conn, callID: id, side: side, epoch: randomEpoch(), protocolVersion: version, outbound: make(chan []byte, outboundCapacity), control: make(chan []byte, 4), done: make(chan struct{})}
	started, paired, stats := time.Now(), h.add(p), connectionStats{}
	slog.Info("account media joined", "callID", id, "side", side, "epoch", p.epoch, "protocolVersion", version)
	go h.writer(p)
	if paired {
		slog.Info("account media peers paired", "callID", id, "sides", "caller,callee")
		h.sendPeerReady(id)
	}
	closeCode, closeReason := 0, ""
	defer func() {
		h.remove(p)
		p.close(websocket.CloseNormalClosure, "closed")
		slog.Info("account media disconnected", "callID", id, "side", side, "epoch", p.epoch, "durationMilliseconds", time.Since(started).Milliseconds(), "binaryMessages", stats.binaryMessages, "validAudioPackets", stats.validAudioPackets, "audioBytes", stats.audioBytes, "invalidPackets", stats.invalidPackets, "relayedPackets", stats.relayedPackets, "relayFailures", stats.relayFailures, "peerMissingCount", stats.peerMissingCount, "closeCode", closeCode, "closeReason", closeReason)
	}()
	conn.SetReadLimit(encryptedAudioPacketSize)
	_ = conn.SetReadDeadline(time.Now().Add(40 * time.Second))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(40 * time.Second)) })
	firstAudioLogged, violations := false, 0
	windowStarted, windowPackets := time.Now(), 0
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			var closeError *websocket.CloseError
			if errors.As(err, &closeError) {
				closeCode, closeReason = closeError.Code, sanitizeCloseReason(closeError.Text)
			}
			return
		}
		if !h.validator.IsAccepted(id) {
			p.close(websocket.ClosePolicyViolation, "call terminal")
			return
		}
		if time.Since(windowStarted) >= time.Second {
			windowStarted, windowPackets = time.Now(), 0
		}
		windowPackets++
		if windowPackets > 100 {
			p.close(websocket.ClosePolicyViolation, "rate limit")
			return
		}
		if kind != websocket.BinaryMessage || !validPacket(data, id, side, p.protocolVersion) {
			violations++
			stats.invalidPackets++
			if violations >= maxViolations {
				p.close(websocket.CloseProtocolError, "invalid packets")
				return
			}
			continue
		}
		stats.binaryMessages++
		if data[1] == 1 {
			sequenceOffset := 18
			if data[0] == 2 {
				sequenceOffset = 23
			}
			sequence := binary.BigEndian.Uint64(data[sequenceOffset : sequenceOffset+8])
			if p.hasSequence && sequence <= p.lastSequence {
				stats.invalidPackets++
				continue
			}
			p.hasSequence, p.lastSequence = true, sequence
			stats.validAudioPackets++
			stats.audioBytes += 640
			if !firstAudioLogged {
				firstAudioLogged = true
				slog.Info("first valid account audio packet received", "callID", id, "side", side, "packetByteLength", len(data), "sequence", sequence)
			}
		}
		destination := h.other(p)
		if destination == nil {
			stats.peerMissingCount++
			continue
		}
		copyData := append([]byte(nil), data...)
		if destination.enqueueLatest(copyData) {
			stats.relayedPackets++
		} else {
			stats.relayFailures++
		}
	}
}

func (h *Hub) writer(p *peer) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		// Control state must never sit behind stale voice frames.
		select {
		case data := <-p.control:
			if !p.write(data) {
				return
			}
			continue
		default:
		}
		select {
		case data := <-p.control:
			if !p.write(data) {
				return
			}
		case data := <-p.outbound:
			if !p.write(data) {
				return
			}
		case <-ticker.C:
			_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := p.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				p.close(websocket.CloseGoingAway, "heartbeat failed")
				return
			}
		case <-p.done:
			return
		}
	}
}

func (p *peer) write(data []byte) bool {
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := p.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		p.close(websocket.CloseGoingAway, "write failed")
		return false
	}
	return true
}

func (p *peer) close(code int, reason string) {
	p.closeOnce.Do(func() {
		close(p.done)
		_ = p.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		_ = p.conn.Close()
	})
}

// Live voice prefers the newest bounded frame over queueing stale audio.
// A short writer stall therefore drops latency, not the authenticated peer.
func (p *peer) enqueueLatest(data []byte) bool {
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case <-p.done:
		return false
	case p.outbound <- data:
		return true
	default:
	}
	select {
	case <-p.outbound:
	default:
	}
	select {
	case <-p.done:
		return false
	case p.outbound <- data:
		return true
	default:
		return false
	}
}

func (p *peer) enqueueControl(data []byte) bool {
	select {
	case <-p.done:
		return false
	default:
	}
	select {
	case <-p.done:
		return false
	case p.control <- data:
		return true
	}
}

func (h *Hub) add(p *peer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[p.callID] == nil {
		h.peers[p.callID] = map[string]*peer{}
	}
	if old := h.peers[p.callID][p.side]; old != nil {
		old.close(websocket.CloseNormalClosure, "replaced")
	}
	h.peers[p.callID][p.side] = p
	return h.validator.MediaPeerJoined(p.callID, p.side, p.epoch)
}

func (h *Hub) remove(p *peer) {
	h.mu.Lock()
	if h.peers[p.callID] != nil && h.peers[p.callID][p.side] == p {
		delete(h.peers[p.callID], p.side)
		if len(h.peers[p.callID]) == 0 {
			delete(h.peers, p.callID)
		}
		h.validator.MediaPeerLeft(p.callID, p.side, p.epoch)
	}
	h.mu.Unlock()
}

func (h *Hub) other(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[p.callID] == nil || h.peers[p.callID][p.side] != p {
		return nil
	}
	side := "caller"
	if p.side == "caller" {
		side = "callee"
	}
	return h.peers[p.callID][side]
}

func (h *Hub) sendPeerReady(id string) {
	h.mu.Lock()
	caller, callee := h.peers[id]["caller"], h.peers[id]["callee"]
	h.mu.Unlock()
	if caller == nil || callee == nil {
		return
	}
	packet := controlPacket(id, 3)
	for _, p := range []*peer{caller, callee} {
		_ = p.enqueueControl(packet)
	}
}

func (h *Hub) CloseCall(id, reason string) {
	h.mu.Lock()
	peers := h.peers[id]
	delete(h.peers, id)
	h.mu.Unlock()
	for _, p := range peers {
		p.close(websocket.CloseNormalClosure, sanitizeCloseReason(reason))
		h.validator.MediaPeerLeft(id, p.side, p.epoch)
	}
}

func (h *Hub) CloseAll(reason string) {
	h.mu.Lock()
	all := h.peers
	h.peers = map[string]map[string]*peer{}
	h.mu.Unlock()
	for id, peers := range all {
		for _, p := range peers {
			p.close(websocket.CloseGoingAway, sanitizeCloseReason(reason))
			h.validator.MediaPeerLeft(id, p.side, p.epoch)
		}
	}
}

func validPacket(data []byte, id, side string, negotiatedVersion int) bool {
	if len(data) < controlPacketSize || data[1] < 1 || data[1] > 3 {
		return false
	}
	if data[1] != 1 {
		return data[0] == 1 && len(data) == controlPacketSize && uuidString(data[2:18]) == id
	}
	if data[0] == 1 {
		return negotiatedVersion == 1 && len(data) == legacyAudioPacketSize && uuidString(data[2:18]) == id
	}
	if data[0] != 2 || negotiatedVersion != 2 || len(data) != encryptedAudioPacketSize || uuidString(data[2:18]) != id {
		return false
	}
	direction := byte(1)
	if side == "callee" {
		direction = 2
	} else if side != "caller" {
		return false
	}
	if data[18] != direction || binary.BigEndian.Uint32(data[19:23]) == 0 {
		return false
	}
	sequence := binary.BigEndian.Uint64(data[23:31])
	return binary.BigEndian.Uint32(data[39:43]) == binary.BigEndian.Uint32(data[19:23]) && binary.BigEndian.Uint64(data[43:51]) == sequence
}
func strictBearer(value string) (string, bool) {
	if !strings.HasPrefix(value, "Bearer ") || strings.Count(value, " ") != 1 {
		return "", false
	}
	token := strings.TrimPrefix(value, "Bearer ")
	return token, token != ""
}
func controlPacket(id string, kind byte) []byte {
	data := make([]byte, controlPacketSize)
	data[0], data[1] = 1, kind
	raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err == nil && len(raw) == 16 {
		copy(data[2:18], raw)
	}
	return data
}
func randomEpoch() string { return time.Now().UTC().Format("150405.000000000") }
func sanitizeCloseReason(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune("-_.:/", r) {
			return r
		}
		return -1
	}, value)
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
func uuidString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	const chars = "0123456789abcdef"
	out := make([]byte, 36)
	j := 0
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j++
		}
		out[j], out[j+1], j = chars[v>>4], chars[v&15], j+2
	}
	return string(out)
}
