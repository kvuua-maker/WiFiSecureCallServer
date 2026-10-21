package sipgw

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// startTestGateway serves the gateway on a loopback UDP port without the
// production listener loop, so tests can drive it with raw SIP messages.
func startTestGateway(t *testing.T, mutate func(*Config)) (*Gateway, *net.UDPAddr) {
	t.Helper()
	cfg := Config{
		Domain:           "sip.example.com",
		Realm:            "sip.example.com",
		Users:            map[string]string{"alice": "alice-password", "bob": "bob-password"},
		DIDs:             map[string]string{"380441234567": "bob"},
		RegistrationTTL:  5 * time.Minute,
		NonceLifetime:    10 * time.Minute,
		NonceSecret:      []byte(testSecret),
		UserAgent:        "test-gateway",
		RegistrationHost: "sip.example.com",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	gateway, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gateway.srv.ServeUDP(conn) }()
	t.Cleanup(func() { _ = gateway.Close() })
	return gateway, conn.LocalAddr().(*net.UDPAddr)
}

func newSIPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sendSIP(t *testing.T, conn *net.UDPConn, to *net.UDPAddr, message string) string {
	t.Helper()
	if _, err := conn.WriteToUDP([]byte(message), to); err != nil {
		t.Fatalf("write: %v", err)
	}
	buffer := make([]byte, 8192)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buffer[:n])
}

func firstLine(message string) string {
	if index := strings.Index(message, "\r\n"); index >= 0 {
		return message[:index]
	}
	return strings.TrimSpace(message)
}

func headerOf(t *testing.T, message, name string) string {
	t.Helper()
	for _, line := range strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n") {
		if len(line) > len(name) && strings.EqualFold(line[:len(name)+1], name+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

func registerMessage(username, domain string, port int, callID string, seq int) string {
	return fmt.Sprintf(
		"REGISTER sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-%s-%d;rport\r\n"+
			"Max-Forwards: 70\r\n"+
			"From: <sip:%s@%s>;tag=%s\r\n"+
			"To: <sip:%s@%s>\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %d REGISTER\r\n"+
			"Contact: <sip:%s@127.0.0.1:%d>\r\n"+
			"Expires: 120\r\n"+
			"User-Agent: sipgw-test\r\n"+
			"Content-Length: 0\r\n\r\n",
		domain, port, callID, seq, username, domain, callID, username, domain, callID, seq, username, port,
	)
}

func authorizationHeader(t *testing.T, challenge, username, password, method, uri string) string {
	t.Helper()
	response := clientDigest(t, challenge, username, password, method, uri, "testcnonce", "00000001")
	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=MD5, qop=auth, nc=00000001, cnonce="testcnonce"`,
		username, testRealm, nonceOf(t, challenge), uri, response,
	)
}

func TestGatewayChallengesRegistrationAndStoresTheBinding(t *testing.T) {
	gateway, addr := startTestGateway(t, nil)
	client := newSIPClient(t)
	port := client.LocalAddr().(*net.UDPAddr).Port

	unauthenticated := sendSIP(t, client, addr, registerMessage("alice", "sip.example.com", port, "reg-1", 1))
	if !strings.HasPrefix(firstLine(unauthenticated), "SIP/2.0 401") {
		t.Fatalf("first REGISTER = %q, want 401", firstLine(unauthenticated))
	}
	challenge := headerOf(t, unauthenticated, "WWW-Authenticate")
	if !strings.Contains(challenge, "nonce=") {
		t.Fatalf("no challenge nonce: %q", challenge)
	}

	authorization := authorizationHeader(t, challenge, "alice", "alice-password", "REGISTER", "sip:sip.example.com")
	authenticated := sendSIP(t, client, addr, strings.Replace(
		registerMessage("alice", "sip.example.com", port, "reg-1", 2),
		"Content-Length: 0",
		"Authorization: "+authorization+"\r\nContent-Length: 0",
		1,
	))
	if !strings.HasPrefix(firstLine(authenticated), "SIP/2.0 200") {
		t.Fatalf("authenticated REGISTER = %q", firstLine(authenticated))
	}
	contact, ok := gateway.Registrar().Lookup("alice", time.Now())
	if !ok {
		t.Fatal("the registration was not stored")
	}
	if !strings.Contains(contact.URI, fmt.Sprintf("127.0.0.1:%d", port)) {
		t.Fatalf("stored contact = %q", contact.URI)
	}
	if gateway.Stats().Registrations != 1 {
		t.Fatalf("registration counter = %d", gateway.Stats().Registrations)
	}
}

func TestGatewayRejectsWrongPassword(t *testing.T) {
	gateway, addr := startTestGateway(t, nil)
	client := newSIPClient(t)
	port := client.LocalAddr().(*net.UDPAddr).Port
	challenge := headerOf(t, sendSIP(t, client, addr, registerMessage("alice", "sip.example.com", port, "reg-2", 1)), "WWW-Authenticate")
	authorization := authorizationHeader(t, challenge, "alice", "wrong-password", "REGISTER", "sip:sip.example.com")
	response := sendSIP(t, client, addr, strings.Replace(
		registerMessage("alice", "sip.example.com", port, "reg-2", 2),
		"Content-Length: 0",
		"Authorization: "+authorization+"\r\nContent-Length: 0",
		1,
	))
	if !strings.HasPrefix(firstLine(response), "SIP/2.0 401") {
		t.Fatalf("wrong password REGISTER = %q", firstLine(response))
	}
	if _, ok := gateway.Registrar().Lookup("alice", time.Now()); ok {
		t.Fatal("a rejected registration must not create a binding")
	}
}

func TestGatewayAnswersOptions(t *testing.T) {
	_, addr := startTestGateway(t, nil)
	client := newSIPClient(t)
	port := client.LocalAddr().(*net.UDPAddr).Port
	message := fmt.Sprintf(
		"OPTIONS sip:sip.example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-opt;rport\r\n"+
			"Max-Forwards: 70\r\n"+
			"From: <sip:probe@example.com>;tag=opt\r\n"+
			"To: <sip:sip.example.com>\r\n"+
			"Call-ID: options-1\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Content-Length: 0\r\n\r\n", port)
	response := sendSIP(t, client, addr, message)
	if !strings.HasPrefix(firstLine(response), "SIP/2.0 200") {
		t.Fatalf("OPTIONS = %q", firstLine(response))
	}
	if allow := headerOf(t, response, "Allow"); !strings.Contains(allow, "INVITE") {
		t.Fatalf("Allow = %q", allow)
	}
}

// TestGatewayForwardsInviteAndRelaysTheAnswer registers two users and places a
// call between them, with a raw SIP peer standing in for the callee.
func TestGatewayForwardsInviteAndRelaysTheAnswer(t *testing.T) {
	_, addr := startTestGateway(t, nil)
	caller := newSIPClient(t)
	callerPort := caller.LocalAddr().(*net.UDPAddr).Port
	callee := newSIPClient(t)
	calleePort := callee.LocalAddr().(*net.UDPAddr).Port

	register := func(client *net.UDPConn, username, password, callID string, port int) {
		t.Helper()
		challenge := headerOf(t, sendSIP(t, client, addr, registerMessage(username, "sip.example.com", port, callID, 1)), "WWW-Authenticate")
		authorization := authorizationHeader(t, challenge, username, password, "REGISTER", "sip:sip.example.com")
		response := sendSIP(t, client, addr, strings.Replace(
			registerMessage(username, "sip.example.com", port, callID, 2),
			"Content-Length: 0",
			"Authorization: "+authorization+"\r\nContent-Length: 0",
			1,
		))
		if !strings.HasPrefix(firstLine(response), "SIP/2.0 200") {
			t.Fatalf("register %s = %q", username, firstLine(response))
		}
	}
	register(caller, "alice", "alice-password", "reg-alice", callerPort)
	register(callee, "bob", "bob-password", "reg-bob", calleePort)

	challenge := headerOf(t, sendSIP(t, caller, addr, inviteMessage(callerPort, "bob", 1, "")), "Proxy-Authenticate")
	authorization := authorizationHeader(t, challenge, "alice", "alice-password", "INVITE", "sip:bob@sip.example.com")
	invite := inviteMessage(callerPort, "bob", 2, authorization)

	// Send the INVITE without blocking: the callee has to answer first.
	if _, err := caller.WriteToUDP([]byte(invite), addr); err != nil {
		t.Fatalf("write invite: %v", err)
	}

	// The callee receives the forwarded INVITE.
	buffer := make([]byte, 8192)
	_ = callee.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, gatewayAddr, err := callee.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("callee did not receive the INVITE: %v", err)
	}
	forwarded := string(buffer[:n])
	if !strings.HasPrefix(firstLine(forwarded), "INVITE sip:bob@127.0.0.1") {
		t.Fatalf("forwarded request line = %q", firstLine(forwarded))
	}
	if headerOf(t, forwarded, "Authorization") != "" {
		t.Fatal("credentials must not be forwarded upstream")
	}

	sdp := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		fmt.Sprintf("m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n", calleePort)
	answer := fmt.Sprintf(
		"SIP/2.0 200 OK\r\n"+
			"Via: %s\r\n"+
			"From: %s\r\n"+
			"To: %s;tag=bob-tag\r\n"+
			"Call-ID: %s\r\n"+
			"CSeq: %s\r\n"+
			"Contact: <sip:bob@127.0.0.1:%d>\r\n"+
			"Content-Type: application/sdp\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		headerOf(t, forwarded, "Via"),
		headerOf(t, forwarded, "From"),
		headerOf(t, forwarded, "To"),
		headerOf(t, forwarded, "Call-ID"),
		headerOf(t, forwarded, "CSeq"),
		calleePort, len(sdp), sdp,
	)
	if _, err := callee.WriteToUDP([]byte(answer), gatewayAddr); err != nil {
		t.Fatalf("callee answer: %v", err)
	}

	// The caller must see the relayed final response.
	deadline := time.Now().Add(4 * time.Second)
	var relayed string
	for time.Now().Before(deadline) {
		_ = caller.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := caller.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		candidate := string(buffer[:n])
		if strings.HasPrefix(firstLine(candidate), "SIP/2.0 200") {
			relayed = candidate
			break
		}
	}
	if relayed == "" {
		t.Fatal("the 200 OK was not relayed back to the caller")
	}
	if cseq := headerOf(t, relayed, "CSeq"); !strings.Contains(cseq, "INVITE") {
		t.Fatalf("relayed CSeq = %q", cseq)
	}
	if to := headerOf(t, relayed, "To"); !strings.Contains(to, "bob-tag") {
		t.Fatalf("the callee tag was lost: %q", to)
	}
	if contact := headerOf(t, relayed, "Contact"); !strings.Contains(contact, "bob") {
		t.Fatalf("relayed Contact = %q", contact)
	}
}

func TestGatewayRoutesInboundDIDToTheRegisteredDevice(t *testing.T) {
	gateway, addr := startTestGateway(t, func(cfg *Config) {
		// Point the trunk at the test client's network so inbound INVITEs are
		// recognised as coming from the trunk.
		cfg.Trunk = Trunk{Host: "127.0.0.1", Port: 5060, Transport: "udp"}
	})
	device := newSIPClient(t)
	port := device.LocalAddr().(*net.UDPAddr).Port
	challenge := headerOf(t, sendSIP(t, device, addr, registerMessage("bob", "sip.example.com", port, "reg-did", 1)), "WWW-Authenticate")
	authorization := authorizationHeader(t, challenge, "bob", "bob-password", "REGISTER", "sip:sip.example.com")
	response := sendSIP(t, device, addr, strings.Replace(
		registerMessage("bob", "sip.example.com", port, "reg-did", 2),
		"Content-Length: 0",
		"Authorization: "+authorization+"\r\nContent-Length: 0",
		1,
	))
	if !strings.HasPrefix(firstLine(response), "SIP/2.0 200") {
		t.Fatalf("register = %q", firstLine(response))
	}
	if !gateway.Registrar().Registered("bob", time.Now()) {
		t.Fatal("bob is not registered")
	}

	trunkSide := newSIPClient(t)
	trunkPort := trunkSide.LocalAddr().(*net.UDPAddr).Port
	inbound := fmt.Sprintf(
		"INVITE sip:380441234567@sip.example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-did;rport\r\n"+
			"Max-Forwards: 69\r\n"+
			"From: <sip:+380441234567@trunk.example.com>;tag=did\r\n"+
			"To: <sip:380441234567@sip.example.com>\r\n"+
			"Call-ID: inbound-1\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Contact: <sip:trunk@127.0.0.1:%d>\r\n"+
			"Content-Type: application/sdp\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		trunkPort, trunkPort, len(testOffer), testOffer,
	)
	if _, err := trunkSide.WriteToUDP([]byte(inbound), addr); err != nil {
		t.Fatalf("inbound write: %v", err)
	}
	buffer := make([]byte, 8192)
	_ = device.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := device.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("the device did not receive the inbound INVITE: %v", err)
	}
	if !strings.HasPrefix(firstLine(string(buffer[:n])), "INVITE sip:bob@") {
		t.Fatalf("forwarded inbound request line = %q", firstLine(string(buffer[:n])))
	}
	if gateway.Stats().InvitesIn != 1 {
		t.Fatalf("inbound counter = %d", gateway.Stats().InvitesIn)
	}
}

func TestGatewayRejectsUnmappedInboundNumber(t *testing.T) {
	_, addr := startTestGateway(t, func(cfg *Config) {
		cfg.Trunk = Trunk{Host: "127.0.0.1", Port: 5060, Transport: "udp"}
	})
	trunkSide := newSIPClient(t)
	port := trunkSide.LocalAddr().(*net.UDPAddr).Port
	message := fmt.Sprintf(
		"INVITE sip:999999999@sip.example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-unmapped;rport\r\n"+
			"Max-Forwards: 69\r\n"+
			"From: <sip:999999999@trunk.example.com>;tag=x\r\n"+
			"To: <sip:999999999@sip.example.com>\r\n"+
			"Call-ID: inbound-2\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Content-Length: 0\r\n\r\n", port)
	response := sendSIP(t, trunkSide, addr, message)
	if !strings.HasPrefix(firstLine(response), "SIP/2.0 404") {
		t.Fatalf("unmapped number = %q, want 404", firstLine(response))
	}
}

func inviteMessage(port int, callee string, seq int, authorization string) string {
	sdp := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		fmt.Sprintf("m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n", port+1000)
	auth := ""
	if authorization != "" {
		auth = "Proxy-Authorization: " + authorization + "\r\n"
	}
	return fmt.Sprintf(
		"INVITE sip:%s@sip.example.com SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK-inv-%d;rport\r\n"+
			"Max-Forwards: 70\r\n"+
			"From: <sip:alice@sip.example.com>;tag=caller\r\n"+
			"To: <sip:%s@sip.example.com>\r\n"+
			"Call-ID: call-%d\r\n"+
			"CSeq: %d INVITE\r\n"+
			"Contact: <sip:alice@127.0.0.1:%d>\r\n"+
			"%s"+
			"Content-Type: application/sdp\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		callee, port, seq, callee, seq, seq, port, auth, len(sdp), sdp,
	)
}

func TestContactURITowardsSourceRewritesPrivateAddresses(t *testing.T) {
	cases := []struct {
		name    string
		contact string
		source  string
		want    string
	}{
		{"private host", "sip:watch1@192.168.1.7:5060", "203.0.113.5:62000", "sip:watch1@203.0.113.5:62000"},
		{"unspecified host", "sip:watch1@0.0.0.0:5060", "203.0.113.5:62000", "sip:watch1@203.0.113.5:62000"},
		{"loopback host", "sip:watch1@127.0.0.1:5060", "203.0.113.5:62000", "sip:watch1@203.0.113.5:62000"},
		{"public host is kept", "sip:watch1@198.51.100.9:5070", "203.0.113.5:62000", "sip:watch1@198.51.100.9:5070"},
		{"host name is kept", "sip:watch1@watch.example.com:5060", "203.0.113.5:62000", "sip:watch1@watch.example.com:5060"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := contactURITowardsSource(tc.contact, tc.source); got != tc.want {
				t.Fatalf("contact = %q, want %q", got, tc.want)
			}
		})
	}
}
