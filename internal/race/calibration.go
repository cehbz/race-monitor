package race

import (
	"bytes"
	"encoding/binary"
	"net/netip"

	"github.com/cehbz/race-monitor/internal/bpf"
)

const (
	// calibrationMinVotes is the number of independent peer_connection*
	// matches at the same offset required to lock in the calibration.
	calibrationMinVotes = 2

	// sockaddrINSize is the number of bytes in a sockaddr_in that we
	// match: sin_family (2) + sin_port (2) + sin_addr (4).
	sockaddrINSize = 8

	// calibrationDataSize matches CALIBRATION_READ_SIZE in probe.c.
	calibrationDataSize = 512

	// peerIDSize is the BT protocol peer_id length (always 20 bytes).
	peerIDSize = 20

	// peerIDMinMatchLen is the minimum prefix length for peer_id pattern
	// matching during calibration. The Azureus-style prefix is 8 bytes
	// (e.g., "-qB4530-"); we require at least this many bytes.
	peerIDMinMatchLen = 8
)

// calibrationState tracks the auto-calibration of both the m_remote sockaddr_in
// offset and the m_peer_id offset within the peer_connection struct.
//
// The algorithm runs in two phases:
//
// Phase 1 (sockaddr_in): Scan 512-byte dumps for known peer IP:port patterns.
// Lock offset after ≥2 independent matches at the same byte position.
//
// Phase 2 (peer_id): After sockaddr_in is locked, correlate each dump to a
// specific API peer via extracted IP:port. Search for the known peer_id bytes
// from the API in the same dump. Lock peer_id offset after ≥2 matches.
//
// After both offsets are locked, all peer metadata (IP, port, peer_id) can be
// extracted deterministically from eBPF captures without further API polling.
type calibrationState struct {
	offset       int         // discovered sockaddr_in offset, -1 if uncalibrated
	peerIDOffset int         // discovered peer_id offset, -1 if uncalibrated
	votes        map[int]int // sockaddr_in candidate offset → match count
	peerIDVotes  map[int]int // peer_id candidate offset → match count
	pending      []bpf.CalibrationEvent
	// matchedPtrs tracks which peer_connection* pointers have already voted
	// at each offset, preventing duplicate votes from re-scans.
	matchedPtrs       map[int]map[uint64]bool // sockaddr offset → set of obj_ptrs that voted
	peerIDMatchedPtrs map[int]map[uint64]bool // peer_id offset → set of obj_ptrs that voted
}

func newCalibrationState() *calibrationState {
	return &calibrationState{
		offset:            -1,
		peerIDOffset:      -1,
		votes:             make(map[int]int),
		peerIDVotes:       make(map[int]int),
		matchedPtrs:       make(map[int]map[uint64]bool),
		peerIDMatchedPtrs: make(map[int]map[uint64]bool),
	}
}

// newCalibratedState creates a pre-calibrated state from cached offsets.
func newCalibratedState(sockaddrOffset, peerIDOffset int) *calibrationState {
	return &calibrationState{
		offset:            sockaddrOffset,
		peerIDOffset:      peerIDOffset,
		votes:             make(map[int]int),
		peerIDVotes:       make(map[int]int),
		matchedPtrs:       make(map[int]map[uint64]bool),
		peerIDMatchedPtrs: make(map[int]map[uint64]bool),
	}
}

func (cs *calibrationState) isCalibrated() bool {
	return cs.offset >= 0
}

// isFullyCalibrated returns true when both sockaddr_in and peer_id offsets
// have been discovered. After this point, all peer metadata can be extracted
// from eBPF captures without API polling.
func (cs *calibrationState) isFullyCalibrated() bool {
	return cs.offset >= 0 && cs.peerIDOffset >= 0
}

// tryCalibrate attempts to discover the sockaddr_in offset by scanning the
// 512-byte calibration data for known peer IP:port patterns.
//
// A sockaddr_in is identified by: AF_INET (0x0002 LE) at offset, followed by
// port in network byte order (big-endian), followed by IPv4 address in network
// byte order (big-endian).
//
// Returns true if the calibration locked in (offset discovered).
func (cs *calibrationState) tryCalibrate(cal bpf.CalibrationEvent, knownPeers map[netip.AddrPort]bool) bool {
	if cs.isCalibrated() {
		return true
	}

	if len(knownPeers) == 0 {
		return false
	}

	for offset := 0; offset <= calibrationDataSize-sockaddrINSize; offset++ {
		addr, ok := parseSockaddrIN(cal.Data[:], offset)
		if !ok {
			continue
		}

		if !knownPeers[addr] {
			continue
		}

		// Ensure this ptr hasn't already voted at this offset
		if cs.matchedPtrs[offset] == nil {
			cs.matchedPtrs[offset] = make(map[uint64]bool)
		}
		if cs.matchedPtrs[offset][cal.ObjPtr] {
			continue
		}
		cs.matchedPtrs[offset][cal.ObjPtr] = true

		cs.votes[offset]++
		if cs.votes[offset] >= calibrationMinVotes {
			cs.offset = offset
			return true
		}
	}

	return false
}

// extractEndpoint extracts the IP:port from calibration data at the locked
// offset. Returns ok=false if not calibrated or if the data at the offset
// doesn't contain a valid sockaddr_in.
func (cs *calibrationState) extractEndpoint(data [calibrationDataSize]byte) (netip.AddrPort, bool) {
	if !cs.isCalibrated() {
		return netip.AddrPort{}, false
	}
	return parseSockaddrIN(data[:], cs.offset)
}

// tryCalibratePeerID attempts to discover the peer_id offset by correlating
// calibration data with known peer IDs from the API. Requires sockaddr_in
// calibration to be complete (so we can identify which peer a dump belongs to).
//
// Returns true if the peer_id offset was locked in.
func (cs *calibrationState) tryCalibratePeerID(cal bpf.CalibrationEvent, knownPeerIDs map[netip.AddrPort]string) bool {
	if cs.peerIDOffset >= 0 {
		return true
	}

	if !cs.isCalibrated() {
		return false // need sockaddr_in offset first
	}

	// Extract IP:port to identify this peer
	addr, ok := cs.extractEndpoint(cal.Data)
	if !ok {
		return false
	}

	// Look up the expected peer_id for this IP:port
	expectedPeerID, ok := knownPeerIDs[addr]
	if !ok || len(expectedPeerID) < peerIDMinMatchLen {
		return false
	}

	// Search for the peer_id bytes in the dump. Use the minimum of the
	// available peer_id length and the full 20-byte peer_id size.
	searchBytes := []byte(expectedPeerID)
	if len(searchBytes) > peerIDSize {
		searchBytes = searchBytes[:peerIDSize]
	}

	for offset := 0; offset <= calibrationDataSize-len(searchBytes); offset++ {
		if !bytes.Equal(cal.Data[offset:offset+len(searchBytes)], searchBytes) {
			continue
		}

		// Ensure this ptr hasn't already voted at this offset
		if cs.peerIDMatchedPtrs[offset] == nil {
			cs.peerIDMatchedPtrs[offset] = make(map[uint64]bool)
		}
		if cs.peerIDMatchedPtrs[offset][cal.ObjPtr] {
			continue
		}
		cs.peerIDMatchedPtrs[offset][cal.ObjPtr] = true

		cs.peerIDVotes[offset]++
		if cs.peerIDVotes[offset] >= calibrationMinVotes {
			cs.peerIDOffset = offset
			return true
		}
	}

	return false
}

// extractPeerID extracts the 20-byte BT peer_id from calibration data at the
// locked peer_id offset. Returns the raw peer_id bytes as a string and true
// if successful. Returns empty and false if not calibrated or out of bounds.
func (cs *calibrationState) extractPeerID(data [calibrationDataSize]byte) (string, bool) {
	if cs.peerIDOffset < 0 {
		return "", false
	}
	if cs.peerIDOffset+peerIDSize > calibrationDataSize {
		return "", false
	}
	raw := data[cs.peerIDOffset : cs.peerIDOffset+peerIDSize]
	return string(raw), true
}

// decodePeerClient decodes the BT client name from a raw 20-byte peer_id.
// Handles the Azureus-style format: -XXYYYY- where XX is a 2-letter client
// code and YYYY is the version. Returns empty string for unrecognized formats.
func decodePeerClient(peerID string) string {
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

// parseSockaddrIN attempts to parse a sockaddr_in at the given byte offset.
// Returns the parsed AddrPort and true if valid, or zero and false otherwise.
//
// sockaddr_in layout (16 bytes total, we check first 8):
//
//	offset+0: uint16 sin_family  = AF_INET (2), host byte order (LE on x86)
//	offset+2: uint16 sin_port    = port, network byte order (BE)
//	offset+4: uint32 sin_addr    = IPv4 address, network byte order (BE)
func parseSockaddrIN(data []byte, offset int) (netip.AddrPort, bool) {
	if offset < 0 || offset+sockaddrINSize > len(data) {
		return netip.AddrPort{}, false
	}

	// Check AF_INET in little-endian (host byte order on x86_64)
	family := binary.LittleEndian.Uint16(data[offset:])
	if family != 2 { // AF_INET
		return netip.AddrPort{}, false
	}

	// Port in network byte order (big-endian)
	port := binary.BigEndian.Uint16(data[offset+2:])
	if port == 0 {
		return netip.AddrPort{}, false
	}

	// IPv4 address in network byte order
	ip4Bytes := [4]byte{data[offset+4], data[offset+5], data[offset+6], data[offset+7]}
	addr := netip.AddrFrom4(ip4Bytes)

	// Reject unspecified and loopback addresses — they're noise, not real peers
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
		return netip.AddrPort{}, false
	}

	return netip.AddrPortFrom(addr, port), true
}
