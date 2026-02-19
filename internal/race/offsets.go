package race

import (
	"encoding/binary"
	"net/netip"
)

const (
	// dumpDataSize matches DUMP_READ_SIZE in probe.c.
	dumpDataSize = 4096

	// sockaddrINSize is sin_family (2) + sin_port (2) + sin_addr (4).
	sockaddrINSize = 8

	// infoHashSize is the SHA-1 info_hash length (always 20 bytes).
	infoHashSize = 20

	// peerIDSize is the BT protocol peer_id length (always 20 bytes).
	peerIDSize = 20
)

// CalibratedOffsets holds the 4 byte offsets discovered during calibration.
// All offsets are non-negative; -1 means not calibrated.
type CalibratedOffsets struct {
	SockaddrOffset   int // sockaddr_in within peer_connection struct
	PeerIDOffset     int // peer_id within peer_connection struct
	InfoHashOffset   int // info_hash within torrent struct
	TorrentPtrOffset int // torrent* pointer within peer_connection struct
}

// ExtractInfoHash reads the 20-byte info_hash from a torrent struct dump.
func ExtractInfoHash(data [dumpDataSize]byte, offset int) ([]byte, bool) {
	if offset < 0 || offset+infoHashSize > dumpDataSize {
		return nil, false
	}
	raw := make([]byte, infoHashSize)
	copy(raw, data[offset:offset+infoHashSize])
	return raw, true
}

// ExtractTorrentPtr reads the torrent* pointer from a peer_connection dump
// at the given offset (8-byte aligned).
func ExtractTorrentPtr(data [dumpDataSize]byte, offset int) (uint64, bool) {
	if offset < 0 || offset+8 > dumpDataSize {
		return 0, false
	}
	ptr := binary.LittleEndian.Uint64(data[offset : offset+8])
	return ptr, ptr != 0
}

// ExtractEndpoint reads the sockaddr_in (AF_INET) at the given offset,
// returning the IP:port. Returns ok=false if the data doesn't contain
// a valid sockaddr_in.
func ExtractEndpoint(data [dumpDataSize]byte, offset int) (netip.AddrPort, bool) {
	if offset < 0 || offset+sockaddrINSize > dumpDataSize {
		return netip.AddrPort{}, false
	}

	// AF_INET in little-endian (host byte order on x86_64)
	family := binary.LittleEndian.Uint16(data[offset:])
	if family != 2 {
		return netip.AddrPort{}, false
	}

	// Port in network byte order (big-endian)
	port := binary.BigEndian.Uint16(data[offset+2:])
	if port == 0 {
		return netip.AddrPort{}, false
	}

	// IPv4 address in network byte order
	ip4 := [4]byte{data[offset+4], data[offset+5], data[offset+6], data[offset+7]}
	addr := netip.AddrFrom4(ip4)
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
		return netip.AddrPort{}, false
	}

	return netip.AddrPortFrom(addr, port), true
}

// ExtractPeerID reads the 20-byte BT peer_id from a peer_connection dump.
func ExtractPeerID(data [dumpDataSize]byte, offset int) (string, bool) {
	if offset < 0 || offset+peerIDSize > dumpDataSize {
		return "", false
	}
	return string(data[offset : offset+peerIDSize]), true
}

// DecodePeerClient decodes the BT client name from a raw 20-byte peer_id.
// Handles the Azureus-style format: -XXYYYY- where XX is a 2-letter client
// code and YYYY is the version.
func DecodePeerClient(peerID string) string {
	if len(peerID) < 8 {
		return ""
	}
	b := []byte(peerID)

	// Azureus style: first byte '-', 8th byte '-'
	if b[0] == '-' && b[7] == '-' {
		clientCode := string(b[1:3])
		version := string(b[3:7])
		switch clientCode {
		case "qB":
			return "qBittorrent " + version
		case "DE":
			return "Deluge " + version
		case "TR":
			return "Transmission " + version
		case "UT":
			return "uTorrent " + version
		case "lt":
			return "libtorrent " + version
		case "AZ":
			return "Azureus " + version
		case "LT":
			return "libtorrent " + version
		case "SD":
			return "Thunder " + version
		case "XL":
			return "Xunlei " + version
		default:
			return clientCode + " " + version
		}
	}

	return ""
}
