package sipgw

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// mediaRelay forwards RTP between a registered device and the trunk.
//
// It exists because the watch cannot be dialled directly from the public
// internet: it sits behind a home router, while the trunk sends media to the
// address it was given in SDP. The relay gives each leg its own port on the VPS
// and forwards packets to the address learned from the other leg, which is the
// standard symmetric-RTP arrangement.
//
// SRTP is not terminated: crypto attributes in SDP are passed through untouched,
// so an encrypted media stream stays end to end. Only addresses and the audio
// port are rewritten.
type mediaRelay struct {
	id          string
	bindAddress string

	// watch is the socket advertised to the registered device.
	watch *net.UDPConn
	// trunk is the socket advertised to the trunk.
	trunk *net.UDPConn

	// watchDest is where packets arriving from the device are sent: the media
	// address the trunk published in SDP.
	watchDest atomic.Pointer[net.UDPAddr]
	// trunkDest is where packets arriving from the trunk are sent: the source
	// address the device was seen at.
	trunkDest atomic.Pointer[net.UDPAddr]

	closed  atomic.Bool
	wg      sync.WaitGroup
	relayed atomic.Uint64
	dropped atomic.Uint64
}

// newMediaRelay binds one socket for each leg on bindAddress.
func newMediaRelay(id, bindAddress string) (*mediaRelay, error) {
	host := bindAddress
	if parsedHost, _, err := net.SplitHostPort(bindAddress); err == nil {
		host = parsedHost
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("media relay: %q is not an IP address", host)
	}
	watchConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, fmt.Errorf("media relay: watch socket: %w", err)
	}
	trunkConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		_ = watchConn.Close()
		return nil, fmt.Errorf("media relay: trunk socket: %w", err)
	}
	relay := &mediaRelay{
		id:          id,
		bindAddress: host,
		watch:       watchConn,
		trunk:       trunkConn,
	}
	relay.wg.Add(2)
	// Packets from the device go out to the trunk address, and the device's
	// source address becomes the trunk leg's destination.
	go relay.pump(watchConn, trunkConn, &relay.watchDest, &relay.trunkDest)
	// Packets from the trunk go back to the device.
	go relay.pump(trunkConn, watchConn, &relay.trunkDest, nil)
	return relay, nil
}

// watchPort is the port the device is told to send media to.
func (r *mediaRelay) watchPort() int { return r.watch.LocalAddr().(*net.UDPAddr).Port }

// trunkPort is the port the trunk is told to send media to.
func (r *mediaRelay) trunkPort() int { return r.trunk.LocalAddr().(*net.UDPAddr).Port }

// setFarEnd records the trunk media address learned from SDP.
func (r *mediaRelay) setFarEnd(address string, port int, _ bool) {
	if address == "" || port <= 0 {
		return
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return
	}
	r.watchDest.Store(&net.UDPAddr{IP: ip, Port: port})
}

// pump reads from in and writes to out, towards dest.
//
// When learn is set, the source address of arriving packets is stored there,
// which is how the other leg learns where the device actually is after NAT.
func (r *mediaRelay) pump(in, out *net.UDPConn, dest, learn *atomic.Pointer[net.UDPAddr]) {
	defer r.wg.Done()
	buffer := make([]byte, 2048)
	for {
		n, source, err := in.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if r.closed.Load() {
			return
		}
		if learn != nil {
			current := learn.Load()
			if current == nil || !current.IP.Equal(source.IP) || current.Port != source.Port {
				learn.Store(&net.UDPAddr{IP: source.IP, Port: source.Port, Zone: source.Zone})
			}
		}
		target := dest.Load()
		if target == nil {
			r.dropped.Add(1)
			continue
		}
		if _, err := out.WriteToUDP(buffer[:n], target); err != nil {
			r.dropped.Add(1)
			continue
		}
		r.relayed.Add(1)
	}
}

// Close releases both sockets and stops the pumps.
func (r *mediaRelay) Close() {
	if !r.closed.CompareAndSwap(false, true) {
		return
	}
	_ = r.watch.Close()
	_ = r.trunk.Close()
	r.wg.Wait()
}

// RelayStats reports the packet counters of one call.
func (r *mediaRelay) RelayStats() (relayed, dropped uint64) {
	return r.relayed.Load(), r.dropped.Load()
}
