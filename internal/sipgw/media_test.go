package sipgw

import (
	"net"
	"testing"
	"time"
)

func TestMediaRelayForwardsBothDirections(t *testing.T) {
	relay, err := newMediaRelay("test-call", "127.0.0.1")
	if err != nil {
		t.Fatalf("newMediaRelay: %v", err)
	}
	defer relay.Close()

	// The device and the trunk are two plain UDP sockets on loopback.
	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()
	trunk, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("trunk socket: %v", err)
	}
	defer trunk.Close()

	trunkAddr := trunk.LocalAddr().(*net.UDPAddr)
	relay.setFarEnd("127.0.0.1", trunkAddr.Port, false)

	// Device -> relay -> trunk.
	if _, err := device.WriteToUDP([]byte("from-device"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.watchPort()}); err != nil {
		t.Fatalf("device write: %v", err)
	}
	buffer := make([]byte, 64)
	_ = trunk.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := trunk.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("trunk read: %v", err)
	}
	if string(buffer[:n]) != "from-device" {
		t.Fatalf("trunk received %q", buffer[:n])
	}

	// Trunk -> relay -> device (the device address is learned from the packet above).
	if _, err := trunk.WriteToUDP([]byte("from-trunk"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.trunkPort()}); err != nil {
		t.Fatalf("trunk write: %v", err)
	}
	_ = device.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = device.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("device read: %v", err)
	}
	if string(buffer[:n]) != "from-trunk" {
		t.Fatalf("device received %q", buffer[:n])
	}

	if relayed, dropped := relay.RelayStats(); relayed != 2 || dropped != 0 {
		t.Fatalf("relayed=%d dropped=%d", relayed, dropped)
	}
}

func TestMediaRelayDropsUntilTheFarEndIsKnown(t *testing.T) {
	relay, err := newMediaRelay("test-call", "127.0.0.1")
	if err != nil {
		t.Fatalf("newMediaRelay: %v", err)
	}
	defer relay.Close()

	device, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("device socket: %v", err)
	}
	defer device.Close()

	if _, err := device.WriteToUDP([]byte("early"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.watchPort()}); err != nil {
		t.Fatalf("device write: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, dropped := relay.RelayStats(); dropped == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a packet with no known destination was not counted as dropped")
}

func TestMediaRelayRejectsBadBindAddress(t *testing.T) {
	if _, err := newMediaRelay("call", "not-an-address"); err == nil {
		t.Fatal("expected an error for a malformed bind address")
	}
}
