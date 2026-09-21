package media

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
	audioPacketSize   = 674
	controlPacketSize = 34
	outboundCapacity  = 64
	maxViolations     = 5
)

type Validator interface {
	ValidateMedia(id, role, token string) bool
	MediaPeerJoined(id, role, epoch string) bool
	MediaPeerLeft(id, role, epoch string)
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
	callID, role, epoch string
	protocolVersion     int
	outbound            chan []byte
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
	id, role := strings.ToLower(r.URL.Query().Get("callID")), r.URL.Query().Get("role")
	token, ok := strictBearer(r.Header.Get("Authorization"))
	if !ok || !h.validator.ValidateMedia(id, role, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	version := 1
	if r.URL.Query().Get("protocolVersion") == "2" {
		version = 2
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	p := &peer{conn: conn, callID: id, role: role, epoch: randomEpoch(), protocolVersion: version, outbound: make(chan []byte, outboundCapacity), done: make(chan struct{})}
	started := time.Now()
	paired := h.add(p)
	stats := connectionStats{}
	slog.Info("media joined", "callID", id, "role", role, "epoch", p.epoch, "protocolVersion", version)
	go h.writer(p)
	if paired {
		slog.Info("media peers paired", "callID", id, "roles", "A,B")
		h.sendPeerReady(id)
	}
	closeCode, closeReason := 0, ""
	defer func() {
		h.remove(p)
		p.close(websocket.CloseNormalClosure, "closed")
		slog.Info("media disconnected", "callID", id, "role", role, "epoch", p.epoch, "durationMilliseconds", time.Since(started).Milliseconds(), "binaryMessages", stats.binaryMessages, "validAudioPackets", stats.validAudioPackets, "audioBytes", stats.audioBytes, "invalidPackets", stats.invalidPackets, "relayedPackets", stats.relayedPackets, "relayFailures", stats.relayFailures, "peerMissingCount", stats.peerMissingCount, "closeCode", closeCode, "closeReason", closeReason)
	}()
	conn.SetReadLimit(audioPacketSize)
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
		if kind != websocket.BinaryMessage || !validPacket(data, id) {
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
			sequence := binary.BigEndian.Uint64(data[18:26])
			if p.hasSequence && sequence <= p.lastSequence {
				stats.invalidPackets++
				continue
			}
			p.hasSequence = true
			p.lastSequence = sequence
			stats.validAudioPackets++
			stats.audioBytes += 640
			if !firstAudioLogged {
				firstAudioLogged = true
				slog.Info("first valid audio packet received", "callID", id, "role", role, "packetByteLength", len(data), "sequence", sequence)
			}
		}
		destination := h.other(p)
		if destination == nil {
			stats.peerMissingCount++
			continue
		}
		copyData := append([]byte(nil), data...)
		select {
		case destination.outbound <- copyData:
			stats.relayedPackets++
		default:
			stats.relayFailures++
			destination.close(websocket.ClosePolicyViolation, "relay overflow")
		}
	}
}

func (h *Hub) writer(p *peer) {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case data := <-p.outbound:
			_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := p.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				p.close(websocket.CloseGoingAway, "write failed")
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

func (p *peer) close(code int, reason string) {
	p.closeOnce.Do(func() {
		close(p.done)
		_ = p.conn.SetWriteDeadline(time.Now().Add(time.Second))
		_ = p.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		_ = p.conn.Close()
	})
}

func (h *Hub) add(p *peer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[p.callID] == nil {
		h.peers[p.callID] = map[string]*peer{}
	}
	if old := h.peers[p.callID][p.role]; old != nil {
		old.close(websocket.CloseNormalClosure, "replaced")
	}
	h.peers[p.callID][p.role] = p
	return h.validator.MediaPeerJoined(p.callID, p.role, p.epoch)
}
func (h *Hub) remove(p *peer) {
	h.mu.Lock()
	if h.peers[p.callID] != nil && h.peers[p.callID][p.role] == p {
		delete(h.peers[p.callID], p.role)
		if len(h.peers[p.callID]) == 0 {
			delete(h.peers, p.callID)
		}
		h.validator.MediaPeerLeft(p.callID, p.role, p.epoch)
	}
	h.mu.Unlock()
}
func (h *Hub) other(p *peer) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[p.callID] == nil || h.peers[p.callID][p.role] != p {
		return nil
	}
	role := "A"
	if p.role == "A" {
		role = "B"
	}
	return h.peers[p.callID][role]
}
func (h *Hub) sendPeerReady(id string) {
	h.mu.Lock()
	a, b := h.peers[id]["A"], h.peers[id]["B"]
	h.mu.Unlock()
	if a == nil || b == nil || a.protocolVersion < 2 || b.protocolVersion < 2 {
		return
	}
	packet := controlPacket(id, 3)
	for _, p := range []*peer{a, b} {
		select {
		case p.outbound <- packet:
		default:
			p.close(websocket.ClosePolicyViolation, "ready overflow")
		}
	}
}
func (h *Hub) CloseCall(id, reason string) {
	h.mu.Lock()
	peers := h.peers[id]
	delete(h.peers, id)
	h.mu.Unlock()
	for _, p := range peers {
		p.close(websocket.CloseNormalClosure, sanitizeCloseReason(reason))
		h.validator.MediaPeerLeft(id, p.role, p.epoch)
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
			h.validator.MediaPeerLeft(id, p.role, p.epoch)
		}
	}
}

func validPacket(data []byte, id string) bool {
	if len(data) != audioPacketSize && len(data) != controlPacketSize || data[0] != 1 || data[1] < 1 || data[1] > 3 {
		return false
	}
	if data[1] == 1 && len(data) != audioPacketSize {
		return false
	}
	if data[1] != 1 && len(data) != controlPacketSize {
		return false
	}
	return uuidString(data[2:18]) == id
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
