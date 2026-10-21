package sipgw

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Stats is a point-in-time view of gateway activity.
type Stats struct {
	StartedAt         time.Time `json:"startedAt"`
	Registrations     uint64    `json:"registrations"`
	RegistrationFails uint64    `json:"registrationFailures"`
	InvitesOut        uint64    `json:"invitesOutbound"`
	InvitesIn         uint64    `json:"invitesInbound"`
	InvitesRejected   uint64    `json:"invitesRejected"`
	ActiveCalls       int64     `json:"activeCalls"`
	MediaRelayed      uint64    `json:"mediaPacketsRelayed"`
	MediaDropped      uint64    `json:"mediaPacketsDropped"`
}

// Gateway is the SIP registrar and signalling proxy.
type Gateway struct {
	cfg    Config
	log    *slog.Logger
	ua     *sipgo.UserAgent
	srv    *sipgo.Server
	client *sipgo.Client
	reg    *Registrar
	auth   *Authenticator

	startedAt time.Time

	mu      sync.Mutex
	callIDs map[string]*call

	counters struct {
		registrations     atomic.Uint64
		registrationFails atomic.Uint64
		invitesOut        atomic.Uint64
		invitesIn         atomic.Uint64
		invitesRejected   atomic.Uint64
		activeCalls       atomic.Int64
	}

	mediaBind   string
	mediaPublic string
}

type call struct {
	id string
	// watchSide is true when the request originated from a registered device,
	// false when it arrived from the trunk.
	watchSide bool
	media     *mediaRelay
	createdAt time.Time
	// nextHop is the URI in-dialog requests must be sent to.
	nextHop   string
	transport string
	// cancelUpstream stops the pending INVITE when the caller hangs up.
	cancelUpstream func()
}

// New builds a gateway. It does not listen until Start is called.
func New(cfg Config, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = slog.Default()
	}
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent(cfg.UserAgent),
		sipgo.WithUserAgentHostname(cfg.Domain),
	)
	if err != nil {
		return nil, fmt.Errorf("sipgw: user agent: %w", err)
	}
	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(logger))
	if err != nil {
		_ = ua.Close()
		return nil, fmt.Errorf("sipgw: server: %w", err)
	}
	client, err := sipgo.NewClient(ua, sipgo.WithClientHostname(cfg.Domain), sipgo.WithClientLogger(logger))
	if err != nil {
		_ = ua.Close()
		return nil, fmt.Errorf("sipgw: client: %w", err)
	}
	g := &Gateway{
		cfg:         cfg,
		log:         logger.With("component", "sipgw"),
		ua:          ua,
		srv:         srv,
		client:      client,
		reg:         NewRegistrar(),
		auth:        NewAuthenticator(cfg.Realm, cfg.Users, cfg.NonceSecret, cfg.NonceLifetime),
		startedAt:   time.Now(),
		callIDs:     map[string]*call{},
		mediaBind:   cfg.MediaBindAddress(),
		mediaPublic: cfg.MediaPublicIP,
	}
	g.registerHandlers()
	return g, nil
}

// Registrar exposes the registry for the status endpoint.
func (g *Gateway) Registrar() *Registrar { return g.reg }

// Stats returns a snapshot of the counters.
func (g *Gateway) Stats() Stats {
	g.mu.Lock()
	active := len(g.callIDs)
	g.mu.Unlock()
	return Stats{
		StartedAt:         g.startedAt,
		Registrations:     g.counters.registrations.Load(),
		RegistrationFails: g.counters.registrationFails.Load(),
		InvitesOut:        g.counters.invitesOut.Load(),
		InvitesIn:         g.counters.invitesIn.Load(),
		InvitesRejected:   g.counters.invitesRejected.Load(),
		ActiveCalls:       int64(active),
	}
}

// Close releases the sockets and transactions of the gateway.
func (g *Gateway) Close() error {
	g.mu.Lock()
	for id, c := range g.callIDs {
		if c.media != nil {
			c.media.Close()
		}
		delete(g.callIDs, id)
	}
	g.mu.Unlock()
	if err := g.srv.Close(); err != nil {
		return err
	}
	return g.ua.Close()
}

func (g *Gateway) registerHandlers() {
	g.srv.OnOptions(g.handleOptions)
	g.srv.OnRegister(g.handleRegister)
	g.srv.OnInvite(g.handleInvite)
	g.srv.OnAck(g.handleAck)
	g.srv.OnBye(g.handleBye)
	g.srv.OnCancel(g.handleCancel)
	g.srv.OnInfo(g.handleInfo)
	g.srv.OnNoRoute(func(req *sip.Request, tx sip.ServerTransaction) {
		g.log.Warn("no route", "method", req.Method.String(), "uri", req.Recipient.String())
		g.respond(tx, req, sip.StatusNotFound, "Not Found")
	})
}

// Start begins listening and blocks until ctx is cancelled or a listener fails.
func (g *Gateway) Start(ctx context.Context) error {
	cert, err := g.loadCertificate()
	if err != nil {
		return err
	}
	errs := make(chan error, 3)
	started := 0

	if g.cfg.ListenUDP != "" {
		started++
		go func() {
			g.log.Info("sip udp listening", "address", g.cfg.ListenUDP)
			errs <- g.srv.ListenAndServe(ctx, "udp", g.cfg.ListenUDP)
		}()
	}
	if g.cfg.ListenTLS != "" && cert != nil {
		started++
		go func() {
			g.log.Info("sip tls listening", "address", g.cfg.ListenTLS)
			errs <- g.srv.ListenAndServeTLS(ctx, "tls", g.cfg.ListenTLS, &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			})
		}()
	}
	if g.cfg.ListenWSS != "" && cert != nil {
		started++
		go func() {
			g.log.Info("sip wss listening", "address", g.cfg.ListenWSS)
			errs <- g.srv.ListenAndServeTLS(ctx, "wss", g.cfg.ListenWSS, &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			})
		}()
	}
	if started == 0 {
		return errors.New("sipgw: no listener configured")
	}

	go g.pruneLoop(ctx)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func (g *Gateway) loadCertificate() (*tls.Certificate, error) {
	if g.cfg.TLSCert == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(g.cfg.TLSCert, g.cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("sipgw: tls key pair: %w", err)
	}
	return &cert, nil
}

func (g *Gateway) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			removed := g.reg.Prune(now)
			if removed > 0 {
				g.log.Info("expired registrations pruned", "count", removed)
			}
			g.expireCalls(now)
		}
	}
}

// expireCalls tears down relays of calls that ended without a BYE.
func (g *Gateway) expireCalls(now time.Time) {
	var stale []*call
	g.mu.Lock()
	for id, c := range g.callIDs {
		if now.Sub(c.createdAt) > 4*time.Hour {
			stale = append(stale, c)
			delete(g.callIDs, id)
		}
	}
	g.mu.Unlock()
	for _, c := range stale {
		if c.media != nil {
			c.media.Close()
		}
	}
}

func (g *Gateway) handleOptions(req *sip.Request, tx sip.ServerTransaction) {
	res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
	res.AppendHeader(sip.NewHeader("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, INFO"))
	res.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
	res.AppendHeader(sip.NewHeader("Supported", "path, outbound"))
	_ = tx.Respond(res)
}

func (g *Gateway) handleRegister(req *sip.Request, tx sip.ServerTransaction) {
	auth := g.auth.Verify(headerValues(req, "Authorization"), req.Method.String(), req.Recipient.String())
	if !auth.OK {
		g.counters.registrationFails.Add(1)
		res := sip.NewResponseFromRequest(req, sip.StatusUnauthorized, "Unauthorized", nil)
		res.AppendHeader(sip.NewHeader("WWW-Authenticate", auth.Challenge))
		_ = tx.Respond(res)
		return
	}

	now := time.Now()
	ttl := g.cfg.RegistrationTTL
	if header := req.GetHeaders("Expires"); len(header) > 0 {
		if parsed, err := strconv.Atoi(strings.TrimSpace(header[0].Value())); err == nil {
			if parsed <= 0 {
				ttl = 0
			} else if seconds := time.Duration(parsed) * time.Second; seconds < ttl {
				ttl = seconds
			}
		}
	}

	contacts := parseContacts(req, g.cfg, g.registrationHostFor(req))
	if len(contacts) == 0 && ttl > 0 {
		g.respond(tx, req, sip.StatusBadRequest, "Contact is required")
		return
	}
	if len(contacts) == 0 {
		g.reg.Unregister(auth.Username)
	} else {
		for _, contact := range contacts {
			if contact.ExpiresAt.IsZero() {
				contact.ExpiresAt = now.Add(ttl)
			}
			contact.Source = req.Source()
			contact.UserAgent = headerValue(req, "User-Agent")
			g.reg.Register(auth.Username, contact, ttl, now)
		}
		g.counters.registrations.Add(1)
	}

	res := sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil)
	res.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(int(ttl/time.Second))))
	if contact, ok := g.reg.Lookup(auth.Username, now); ok && ttl > 0 {
		res.AppendHeader(sip.NewHeader("Contact", "<"+contact.URI+">;expires="+strconv.Itoa(int(ttl/time.Second))))
	}
	_ = tx.Respond(res)
	g.log.Info("registration", "user", auth.Username, "ttl", ttl.String(), "source", req.Source(), "contacts", len(contacts))
}

func (g *Gateway) registrationHostFor(req *sip.Request) string {
	if host := req.Recipient.Host; host != "" {
		return host
	}
	return g.cfg.RegistrationHost
}

func (g *Gateway) handleInvite(req *sip.Request, tx sip.ServerTransaction) {
	now := time.Now()
	fromTrunk := g.isTrunkSource(req)

	var username string
	if fromTrunk {
		g.counters.invitesIn.Add(1)
		number := NormalizeNumber(req.Recipient.User)
		if user, ok := g.cfg.DIDs[number]; ok {
			username = user
		} else if req.Recipient.Host == g.cfg.Domain && g.cfg.Users[req.Recipient.User] != "" {
			username = req.Recipient.User
		}
		if username == "" {
			g.counters.invitesRejected.Add(1)
			g.log.Warn("inbound call for an unmapped number", "number", number, "source", req.Source())
			g.respond(tx, req, sip.StatusNotFound, "Not Found")
			return
		}
	} else {
		g.counters.invitesOut.Add(1)
		auth := g.auth.Verify(headerValues(req, "Proxy-Authorization"), req.Method.String(), req.Recipient.String())
		if !auth.OK {
			res := sip.NewResponseFromRequest(req, sip.StatusProxyAuthRequired, "Proxy Authentication Required", nil)
			res.AppendHeader(sip.NewHeader("Proxy-Authenticate", auth.Challenge))
			_ = tx.Respond(res)
			return
		}
		username = auth.Username
		if !g.reg.Registered(username, now) {
			// The device must hold a registration to place calls; otherwise a
			// stolen password alone would be enough to use the trunk.
			g.counters.invitesRejected.Add(1)
			g.respond(tx, req, sip.StatusForbidden, "Register first")
			return
		}
	}

	dest, dialled, err := g.route(req, fromTrunk, username)
	if err != nil {
		g.counters.invitesRejected.Add(1)
		g.log.Warn("call routing failed", "error", err, "uri", req.Recipient.String(), "fromTrunk", fromTrunk)
		g.respond(tx, req, sip.StatusNotFound, "Not Found")
		return
	}

	// 100 Trying promptly: the trunk and the watch both give up quickly on silence.
	trying := sip.NewResponseFromRequest(req, sip.StatusTrying, "Trying", nil)
	_ = tx.Respond(trying)

	callID := ""
	if header := req.CallID(); header != nil {
		callID = string(*header)
	}

	body := req.Body()
	var relay *mediaRelay
	if len(body) > 0 && g.cfg.MediaRelayEnabled() {
		offer := parseSDP(body)
		if offer.hasAudio {
			relay, err = newMediaRelay(callID, g.mediaBind)
			if err != nil {
				g.log.Error("media relay allocation failed", "error", err)
				g.respond(tx, req, sip.StatusServiceUnavailable, "No media relay port")
				return
			}
			// The trunk is told to send media to the relay; the device keeps the
			// relay port as the far end of its own leg.
			body = rewriteSDP(body, g.mediaPublic, relay.trunkPort())
		}
	}

	entry := &call{id: callID, watchSide: !fromTrunk, media: relay, createdAt: now, nextHop: dest.String(), transport: g.transportTo(dest, fromTrunk)}
	g.storeCall(entry)

	go g.forwardInvite(req, tx, dest, body, entry, fromTrunk, dialled)
}

// forwardInvite relays an INVITE and its responses until the transaction ends.
func (g *Gateway) forwardInvite(
	req *sip.Request,
	uasTx sip.ServerTransaction,
	dest sip.Uri,
	body []byte,
	entry *call,
	fromTrunk bool,
	dialled string,
) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	out := buildForwardRequest(req, dest, body)
	clientTx, err := g.client.TransactionRequest(ctx, out)
	if err != nil {
		g.endCall(entry.id)
		g.log.Warn("invite could not be sent", "error", err, "dest", dest.String())
		g.respond(uasTx, req, sip.StatusServiceUnavailable, "Upstream unreachable")
		return
	}
	if entry != nil {
		g.attachUpstreamCancel(entry.id, clientTx, out)
	}

	var answered bool
	for res := range clientTx.Responses() {
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			answered = true
		}
		if res.StatusCode == sip.StatusOK && entry != nil && entry.media != nil {
			answer := parseSDP(res.Body())
			if answer.hasAudio {
				entry.media.setFarEnd(answer.address, answer.audioPort, fromTrunk)
				res.SetBody(rewriteSDP(res.Body(), g.mediaPublic, entry.media.watchPort()))
			} else {
				entry.media.Close()
				entry.media = nil
			}
		}
		g.relayResponse(uasTx, req, res)
		if res.StatusCode >= 300 {
			g.endCall(entry.id)
		}
	}
	if !answered {
		g.endCall(entry.id)
	}
	_ = dialled
}

func (g *Gateway) attachUpstreamCancel(callID string, clientTx sip.ClientTransaction, invite *sip.Request) {
	g.mu.Lock()
	if entry, ok := g.callIDs[callID]; ok {
		entry.cancelUpstream = func() {
			cancel := sip.NewRequest(sip.CANCEL, invite.Recipient)
			sip.CopyHeaders("From", invite, cancel)
			sip.CopyHeaders("To", invite, cancel)
			sip.CopyHeaders("Call-ID", invite, cancel)
			sip.CopyHeaders("CSeq", invite, cancel)
			cancel.CSeq().MethodName = sip.CANCEL
			cancel.SetTransport(invite.Transport())
			cancel.SetDestination(invite.Destination())
			ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if _, err := g.client.Do(ctx, cancel); err != nil {
				g.log.Debug("upstream cancel failed", "error", err)
			}
			clientTx.Terminate()
		}
	}
	g.mu.Unlock()
}

func (g *Gateway) handleAck(req *sip.Request, tx sip.ServerTransaction) {
	entry := g.lookupCall(callIDOf(req))
	if entry == nil {
		return
	}
	g.forwardInDialog(req, entry)
}

func (g *Gateway) handleInfo(req *sip.Request, tx sip.ServerTransaction) {
	entry := g.lookupCall(callIDOf(req))
	if entry == nil {
		g.respond(tx, req, sip.StatusCallTransactionDoesNotExists, "Call/Transaction Does Not Exist")
		return
	}
	g.forwardInDialog(req, entry)
	_ = tx
}

func (g *Gateway) handleBye(req *sip.Request, tx sip.ServerTransaction) {
	entry := g.lookupCall(callIDOf(req))
	if entry == nil {
		g.respond(tx, req, sip.StatusCallTransactionDoesNotExists, "Call/Transaction Does Not Exist")
		return
	}
	g.forwardInDialog(req, entry)
	g.respond(tx, req, sip.StatusOK, "OK")
	g.endCall(entry.id)
}

func (g *Gateway) handleCancel(req *sip.Request, tx sip.ServerTransaction) {
	entry := g.lookupCall(callIDOf(req))
	if entry == nil {
		g.respond(tx, req, sip.StatusCallTransactionDoesNotExists, "Call/Transaction Does Not Exist")
		return
	}
	if entry.cancelUpstream != nil {
		entry.cancelUpstream()
	}
	g.respond(tx, req, sip.StatusOK, "OK")
	g.endCall(entry.id)
}

// forwardInDialog sends a request that belongs to an established dialog to the
// stored next hop and relays the final response.
func (g *Gateway) forwardInDialog(req *sip.Request, entry *call) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
		defer cancel()
		var dest sip.Uri
		if err := sip.ParseUri(entry.nextHop, &dest); err != nil {
			g.log.Warn("in-dialog destination is unparsable", "uri", entry.nextHop, "error", err)
			return
		}
		out := buildForwardRequest(req, dest, req.Body())
		res, err := g.client.Do(ctx, out)
		if err != nil {
			g.log.Debug("in-dialog request failed", "method", req.Method.String(), "error", err)
			return
		}
		if req.Method == sip.BYE || req.Method == sip.ACK {
			g.endCall(entry.id)
		}
		_ = res
	}()
}

// route decides the next hop for an INVITE.
//
// A request that names a registered local user is delivered to that device, so
// watch-to-watch calls stay inside the deployment. Anything else is treated as a
// dialled number and handed to the trunk. A request that arrives from the trunk
// is resolved through the DID table.
func (g *Gateway) route(req *sip.Request, fromTrunk bool, username string) (sip.Uri, string, error) {
	target := req.Recipient
	if fromTrunk {
		contact, ok := g.reg.Lookup(username, time.Now())
		if !ok {
			return sip.Uri{}, "", fmt.Errorf("user %q has no live registration", username)
		}
		var uri sip.Uri
		if err := sip.ParseUri(contact.URI, &uri); err != nil {
			return sip.Uri{}, "", fmt.Errorf("registered contact %q is unparsable: %w", contact.URI, err)
		}
		return uri, target.User, nil
	}

	if target.User == "" {
		return sip.Uri{}, "", fmt.Errorf("request URI %q carries no user", target.String())
	}
	if _, known := g.cfg.Users[target.User]; known {
		if contact, ok := g.reg.Lookup(target.User, time.Now()); ok {
			var uri sip.Uri
			if err := sip.ParseUri(contact.URI, &uri); err == nil {
				return uri, target.User, nil
			}
			return sip.Uri{}, "", fmt.Errorf("registered contact %q is unparsable", contact.URI)
		}
		return sip.Uri{}, "", fmt.Errorf("user %q is not registered", target.User)
	}

	number := NormalizeNumber(target.User)
	if number == "" {
		return sip.Uri{}, "", fmt.Errorf("request URI %q carries no dialable number", target.String())
	}
	if !g.cfg.Trunk.Enabled() {
		return sip.Uri{}, "", fmt.Errorf("no trunk is configured and %q is not a local user", number)
	}
	uri := sip.Uri{Scheme: "sip", User: number, Host: g.cfg.Trunk.Host, Port: g.cfg.Trunk.Port}
	if uri.Port == 0 {
		uri.Port = 5060
	}
	return uri, number, nil
}

func (g *Gateway) transportTo(dest sip.Uri, fromTrunk bool) string {
	if fromTrunk {
		return "udp"
	}
	if dest.Host == g.cfg.Trunk.Host {
		return g.cfg.Trunk.Transport
	}
	return "udp"
}

// isTrunkSource reports whether a request arrived from the configured trunk.
func (g *Gateway) isTrunkSource(req *sip.Request) bool {
	if !g.cfg.Trunk.Enabled() {
		return false
	}
	source, err := net.ResolveUDPAddr("udp", req.Source())
	if err != nil {
		return false
	}
	trunk, err := net.ResolveUDPAddr("udp", g.cfg.Trunk.Address())
	if err != nil {
		return false
	}
	return source.IP.Equal(trunk.IP)
}

func (g *Gateway) storeCall(entry *call) {
	if entry == nil || entry.id == "" {
		return
	}
	g.mu.Lock()
	g.callIDs[entry.id] = entry
	g.mu.Unlock()
}

func (g *Gateway) lookupCall(id string) *call {
	if id == "" {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.callIDs[id]
}

func (g *Gateway) endCall(id string) {
	if id == "" {
		return
	}
	g.mu.Lock()
	entry, ok := g.callIDs[id]
	delete(g.callIDs, id)
	g.mu.Unlock()
	if ok && entry.media != nil {
		entry.media.Close()
	}
}

// relayResponse re-emits an upstream response towards the original requester.
//
// The response is rebuilt from the original request so the Via, Call-ID and CSeq
// belong to this hop, then the headers a session needs are copied from upstream.
func (g *Gateway) relayResponse(uasTx sip.ServerTransaction, original *sip.Request, upstream *sip.Response) {
	res := sip.NewResponse(upstream.StatusCode, upstream.Reason)
	sip.CopyHeaders("Via", original, res)
	sip.CopyHeaders("From", original, res)
	if to := upstream.GetHeaders("To"); len(to) > 0 {
		for _, header := range to {
			res.AppendHeader(header)
		}
	} else {
		sip.CopyHeaders("To", original, res)
	}
	sip.CopyHeaders("Call-ID", original, res)
	sip.CopyHeaders("CSeq", original, res)
	for _, name := range []string{
		"Contact", "Content-Type", "Allow", "Supported", "Require",
		"Record-Route", "Session-Expires", "Min-SE", "WWW-Authenticate",
		"Proxy-Authenticate", "Reason", "Retry-After", "Accept",
	} {
		sip.CopyHeaders(name, upstream, res)
	}
	if body := upstream.Body(); len(body) > 0 {
		res.SetBody(body)
	}
	if err := uasTx.Respond(res); err != nil {
		g.log.Debug("response relay failed", "status", upstream.StatusCode, "error", err)
	}
}

func (g *Gateway) respond(tx sip.ServerTransaction, req *sip.Request, status int, reason string) {
	_ = tx.Respond(sip.NewResponseFromRequest(req, status, reason, nil))
}

// buildForwardRequest turns an inbound request into the request sent upstream.
func buildForwardRequest(req *sip.Request, dest sip.Uri, body []byte) *sip.Request {
	out := sip.NewRequest(req.Method, dest)
	for _, name := range []string{"From", "To", "Call-ID", "Contact", "Content-Type", "User-Agent", "Subject", "Supported", "Allow", "Accept"} {
		sip.CopyHeaders(name, req, out)
	}
	if cseq := req.CSeq(); cseq != nil {
		clone := *cseq
		out.AppendHeader(&clone)
	}
	out.AppendHeader(sip.NewHeader("Max-Forwards", "69"))
	if body != nil {
		out.SetBody(body)
	} else if len(req.Body()) > 0 {
		out.SetBody(req.Body())
	}
	transport := strings.ToLower(req.Transport())
	if transport == "" || transport == "ws" || transport == "wss" {
		transport = "udp"
	}
	out.SetTransport(transport)
	return out
}

func callIDOf(req *sip.Request) string {
	if header := req.CallID(); header != nil {
		return string(*header)
	}
	return ""
}

func headerValues(req *sip.Request, name string) []string {
	headers := req.GetHeaders(name)
	values := make([]string, 0, len(headers))
	for _, header := range headers {
		values = append(values, header.Value())
	}
	return values
}

func headerValue(req *sip.Request, name string) string {
	values := headerValues(req, name)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// parseContacts extracts every Contact of a REGISTER, honouring per-contact
// expires parameters and the default TTL.
func parseContacts(req *sip.Request, cfg Config, host string) []Contact {
	var out []Contact
	for _, raw := range headerValues(req, "Contact") {
		for _, part := range splitTopLevel(raw, ',') {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			uri, params, err := parseContactValue(part)
			if err != nil || uri == "" {
				continue
			}
			contact := Contact{URI: uri}
			if expires := params["expires"]; expires != "" {
				if seconds, err := strconv.Atoi(expires); err == nil {
					if seconds <= 0 {
						contact.ExpiresAt = time.Now().Add(-time.Second)
					} else {
						contact.ExpiresAt = time.Now().Add(time.Duration(seconds) * time.Second)
					}
				}
			}
			out = append(out, contact)
		}
	}
	return out
}

// parseContactValue returns the URI and the parameters of one Contact header.
func parseContactValue(value string) (string, map[string]string, error) {
	params := map[string]string{}
	rest := value
	uri := ""
	if start := strings.IndexByte(value, '<'); start >= 0 {
		end := strings.IndexByte(value, '>')
		if end < start {
			return "", nil, fmt.Errorf("angle brackets are unbalanced in contact %q", value)
		}
		uri = strings.TrimSpace(value[start+1 : end])
		rest = value[end+1:]
	} else {
		for _, part := range splitTopLevel(value, ';') {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "@") || strings.HasPrefix(part, "sip:") || strings.HasPrefix(part, "sips:") {
				uri = part
				break
			}
			break
		}
		if index := strings.IndexByte(value, ';'); index >= 0 {
			uri = strings.TrimSpace(value[:index])
			rest = value[index:]
		} else {
			uri = strings.TrimSpace(value)
			rest = ""
		}
	}
	for _, part := range splitTopLevel(rest, ';') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, ok := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if ok {
			params[key] = strings.Trim(strings.TrimSpace(val), `"`)
		} else {
			params[key] = ""
		}
	}
	return uri, params, nil
}

// splitTopLevel splits on sep outside of angle brackets and quotes.
func splitTopLevel(value string, sep byte) []string {
	var parts []string
	var builder strings.Builder
	depth := 0
	quoted := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '"' && !quoted:
			quoted = true
		case c == '"' && quoted:
			quoted = false
		case !quoted && c == '<':
			depth++
		case !quoted && c == '>':
			if depth > 0 {
				depth--
			}
		case !quoted && depth == 0 && c == sep:
			parts = append(parts, builder.String())
			builder.Reset()
			continue
		}
		builder.WriteByte(c)
	}
	parts = append(parts, builder.String())
	return parts
}
