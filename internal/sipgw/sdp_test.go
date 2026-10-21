package sipgw

import (
	"strings"
	"testing"
)

const testOffer = "v=0\r\n" +
	"o=- 1 1 IN IP4 192.0.2.10\r\n" +
	"s=-\r\n" +
	"c=IN IP4 192.0.2.10\r\n" +
	"t=0 0\r\n" +
	"m=audio 49170 RTP/AVP 0 8 101\r\n" +
	"a=rtpmap:0 PCMU/8000\r\n" +
	"a=rtpmap:8 PCMA/8000\r\n" +
	"a=rtpmap:101 telephone-event/8000\r\n" +
	"a=fmtp:101 0-16\r\n" +
	"a=sendrecv\r\n"

func TestParseSDPFindsAudioEndpoint(t *testing.T) {
	info := parseSDP([]byte(testOffer))
	if !info.hasAudio {
		t.Fatal("no audio stream found")
	}
	if info.audioPort != 49170 {
		t.Fatalf("port = %d", info.audioPort)
	}
	if info.address != "192.0.2.10" {
		t.Fatalf("address = %q", info.address)
	}
}

func TestParseSDPHandlesMediaLevelConnection(t *testing.T) {
	body := "v=0\r\n" +
		"o=- 1 1 IN IP4 10.0.0.1\r\n" +
		"c=IN IP4 10.0.0.1\r\n" +
		"t=0 0\r\n" +
		"m=audio 5004 RTP/AVP 0\r\n" +
		"c=IN IP4 203.0.113.7\r\n"
	info := parseSDP([]byte(body))
	if info.address != "203.0.113.7" {
		t.Fatalf("media-level c= must win, got %q", info.address)
	}
}

func TestParseSDPIgnoresVideoOnly(t *testing.T) {
	body := "v=0\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=video 5004 RTP/AVP 96\r\n"
	if parseSDP([]byte(body)).hasAudio {
		t.Fatal("a video-only offer must not be treated as audio")
	}
}

func TestRewriteSDPReplacesAddressAndPort(t *testing.T) {
	out := string(rewriteSDP([]byte(testOffer), "203.0.113.9", 40000))
	if !strings.Contains(out, "c=IN IP4 203.0.113.9") {
		t.Fatalf("connection line was not rewritten:\n%s", out)
	}
	if !strings.Contains(out, "m=audio 40000 RTP/AVP 0 8 101") {
		t.Fatalf("media line was not rewritten:\n%s", out)
	}
	if strings.Count(out, "c=IN IP4 203.0.113.9") != 1 {
		t.Fatalf("expected exactly one rewritten connection line:\n%s", out)
	}
	if !strings.Contains(out, "a=rtpmap:0 PCMU/8000") {
		t.Fatal("codec attributes must be preserved")
	}
	if !strings.HasSuffix(out, "\r\n") {
		t.Fatal("SDP lines must keep CRLF endings")
	}
}

func TestRewriteSDPKeepsCryptoSections(t *testing.T) {
	body := testOffer + "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abcdefghijklmnopqrstuvwx\r\n"
	out := string(rewriteSDP([]byte(body), "203.0.113.9", 40000))
	if !strings.Contains(out, "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:abcdefghijklmnopqrstuvwx") {
		t.Fatal("SRTP parameters must pass through untouched")
	}
}

func TestRewriteSDPAddsMissingConnectionLine(t *testing.T) {
	body := "v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0\r\n"
	out := string(rewriteSDP([]byte(body), "203.0.113.9", 40000))
	if !strings.Contains(out, "c=IN IP4 203.0.113.9") {
		t.Fatalf("a session-level c= line must be added:\n%s", out)
	}
	if strings.Index(out, "c=IN IP4 203.0.113.9") > strings.Index(out, "m=audio") {
		t.Fatal("the added c= line must precede the media section")
	}
}
