package sipgw

import (
	"strconv"
	"strings"
)

// sdpInfo is the part of an SDP body that a signalling proxy has to understand:
// where the other party wants media sent.
type sdpInfo struct {
	hasAudio  bool
	audioPort int
	address   string
}

// parseSDP extracts the audio endpoint of an SDP body.
//
// The parser is deliberately narrow. A SIP proxy does not need to understand
// codecs, only the connection address and the audio port, and it must not
// rewrite anything it does not understand (ICE candidates and crypto attributes
// are passed through untouched).
func parseSDP(body []byte) sdpInfo {
	info := sdpInfo{}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	inAudio := false
	sessionAddress := ""
	audioAddress := ""
	for _, line := range lines {
		line = strings.TrimRight(line, "\r ")
		switch {
		case strings.HasPrefix(line, "m="):
			fields := strings.Fields(line[2:])
			if len(fields) >= 2 && fields[0] == "audio" {
				port, err := strconv.Atoi(strings.SplitN(fields[1], "/", 2)[0])
				if err == nil && port > 0 {
					info.hasAudio = true
					info.audioPort = port
				}
				inAudio = true
			} else {
				inAudio = false
			}
		case strings.HasPrefix(line, "c="):
			fields := strings.Fields(line[2:])
			if len(fields) < 3 {
				continue
			}
			address := fields[2]
			// A c= line may carry a multicast suffix such as 224.2.1.1/127/3.
			if slash := strings.IndexByte(address, '/'); slash >= 0 {
				address = address[:slash]
			}
			if inAudio {
				audioAddress = address
			} else {
				sessionAddress = address
			}
		}
	}
	if audioAddress != "" {
		info.address = audioAddress
	} else {
		info.address = sessionAddress
	}
	return info
}

// rewriteSDP points the audio stream of an SDP body at addr:port.
//
// Every c= line is replaced and the m=audio port is replaced. When the body has
// no c= line at all one is inserted before the first media section, because the
// audio section inherits the session address. Every other line, including
// a=candidate and a=crypto, is copied byte for byte, which keeps SRTP keys and
// ICE candidates end to end.
func rewriteSDP(body []byte, addr string, port int) []byte {
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var out strings.Builder
	sawConnection := false
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(trimmed, "m="):
			fields := strings.Fields(trimmed[2:])
			if len(fields) >= 2 && fields[0] == "audio" {
				out.WriteString("m=audio ")
				out.WriteString(strconv.Itoa(port))
				for _, field := range fields[2:] {
					out.WriteByte(' ')
					out.WriteString(field)
				}
				out.WriteByte('\n')
				continue
			}
		case strings.HasPrefix(trimmed, "c="):
			fields := strings.Fields(trimmed[2:])
			if len(fields) < 3 {
				break
			}
			out.WriteString("c=" + fields[0] + " " + fields[1] + " " + addr + "\n")
			sawConnection = true
			continue
		}
		out.WriteString(trimmed)
		out.WriteByte('\n')
	}
	result := out.String()
	if !sawConnection {
		if index := strings.Index(result, "m="); index >= 0 {
			result = result[:index] + "c=IN IP4 " + addr + "\n" + result[index:]
		}
	}
	return []byte(strings.ReplaceAll(result, "\n", "\r\n"))
}
