package race

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"

	"github.com/cehbz/race-monitor/internal/bpf"
)

const (
	// calibrationMinVotes is the number of independent peer_connection*
	// matches at the same offset required to lock in sockaddr_in and
	// peer_id calibration. Two votes prevents false positives from
	// coincidental 8-byte sockaddr_in pattern matches.
	calibrationMinVotes = 2

	// torrentPtrMinVotes is the vote threshold for torrent_ptr offset
	// calibration. Set to 1 because we're matching a specific 8-byte
	// heap pointer (e.g. 0x7f27dc5ecad0) — the probability of a random
	// 8-byte value matching is ~N_ptrs / 2^64 per offset, which is
	// effectively zero. A single match is conclusive.
	torrentPtrMinVotes = 1

	// sockaddrINSize is the number of bytes in a sockaddr_in that we
	// match: sin_family (2) + sin_port (2) + sin_addr (4).
	sockaddrINSize = 8

	// calibrationDataSize matches CALIBRATION_READ_SIZE in probe.c.
	calibrationDataSize = 4096

	// peerIDSize is the BT protocol peer_id length (always 20 bytes).
	peerIDSize = 20

	// peerIDMinMatchLen is the minimum prefix length for peer_id pattern
	// matching during calibration. The Azureus-style prefix is 8 bytes
	// (e.g., "-qB4530-"); we require at least this many bytes.
	peerIDMinMatchLen = 8

	// infoHashSize is the SHA-1 info_hash length (always 20 bytes).
	infoHashSize = 20
)

// calibrationState tracks the auto-calibration of both the m_remote sockaddr_in
// offset and the m_peer_id offset within the peer_connection struct.
//
// The algorithm runs in two phases:
//
// Phase 1 (sockaddr_in): Scan calibration dumps for known peer IP:port patterns.
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

// tryCalibrate attempts to discover the sockaddr_in offset by scanning
// calibration data for known peer IP:port patterns.
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

// --- Torrent calibration ---
//
// Discovers the info_hash offset within the torrent struct by scanning
// torrent struct dumps for known info_hash patterns.
// Also discovers the torrent* offset within peer_connection structs
// by scanning peer_connection dumps for known torrent* pointer values.

// torrentCalibrationState tracks discovery of:
//   - info_hash offset within the torrent struct
//   - torrent* (parent pointer) offset within the peer_connection struct
type torrentCalibrationState struct {
	// infoHashOffset is the byte offset of the 20-byte info_hash within
	// the torrent struct. -1 if undiscovered.
	infoHashOffset int
	// torrentPtrOffset is the byte offset of the torrent* pointer within
	// the peer_connection struct. -1 if undiscovered.
	torrentPtrOffset int
	torrentPtrVotes  map[int]int             // offset → match count
	torrentPtrPtrs   map[int]map[uint64]bool // offset → set of peer_connection* ptrs that voted

	// pendingTorrentDumps buffers torrent calibration events until we
	// have a known info_hash to search for.
	pendingTorrentDumps []bpf.CalibrationEvent

	// pendingPeerDumps buffers peer_connection dumps until we have
	// known torrent* pointers to search for.
	pendingPeerDumps []bpf.CalibrationEvent
}

func newTorrentCalibrationState() *torrentCalibrationState {
	return &torrentCalibrationState{
		infoHashOffset:   -1,
		torrentPtrOffset: -1,
		torrentPtrVotes:  make(map[int]int),
		torrentPtrPtrs:   make(map[int]map[uint64]bool),
	}
}

func (ts *torrentCalibrationState) isInfoHashCalibrated() bool {
	return ts.infoHashOffset >= 0
}

func (ts *torrentCalibrationState) isTorrentPtrCalibrated() bool {
	return ts.torrentPtrOffset >= 0
}

// tryCalibrateInfoHashByCorrelation discovers the info_hash offset by
// comparing torrent struct dumps from different torrent* pointers. Each
// torrent has a unique 20-byte SHA-1 info_hash at the same offset. By
// scanning for offsets where the 20-byte value is unique across all dumps,
// we can identify the info_hash field without external ground truth.
//
// Requires at least 2 dumps from distinct torrent* pointers. With 2 dumps,
// accepts only if exactly 1 candidate offset remains. With 3+ dumps the
// false-positive rate drops dramatically.
//
// Returns true if the offset was locked in. On failure, numCandidates is the
// count of candidate offsets (0 if not enough dumps).
func (ts *torrentCalibrationState) tryCalibrateInfoHashByCorrelation(dumps []bpf.CalibrationEvent) (success bool, numCandidates int) {
	if ts.isInfoHashCalibrated() {
		return true, 0
	}

	// Collect one dump per unique torrent_ptr
	byPtr := make(map[uint64]int) // ptr → index into dumps
	for i, d := range dumps {
		if _, exists := byPtr[d.ObjPtr]; !exists {
			byPtr[d.ObjPtr] = i
		}
	}
	if len(byPtr) < 2 {
		return false, 0
	}

	// Gather the raw data slices
	datas := make([][]byte, 0, len(byPtr))
	for _, idx := range byPtr {
		datas = append(datas, dumps[idx].Data[:])
	}

	// Scan 8-byte-aligned offsets for 20-byte windows where:
	// 1. All values are non-zero (uninitialized fields are typically zero)
	// 2. All values are unique across dumps (different torrents have different hashes)
	// 3. No value looks like a user-space pointer pair (heuristic filter)
	var candidates []int
	for off := 0; off <= calibrationDataSize-infoHashSize; off += 8 {
		seen := make(map[string]bool, len(datas))
		valid := true

		for _, data := range datas {
			chunk := data[off : off+infoHashSize]

			// Reject all-zero chunks
			allZero := true
			for _, b := range chunk {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				valid = false
				break
			}

			key := string(chunk)
			if seen[key] {
				// Same value in two different torrent dumps → not the info_hash
				valid = false
				break
			}
			seen[key] = true
		}
		if valid {
			candidates = append(candidates, off)
		}
	}

	// Accept only if we have a unique candidate. With 3+ diverse dumps
	// this converges quickly. With 2 dumps, multiple candidates are common
	// so we wait for more data.
	if len(candidates) == 1 {
		ts.infoHashOffset = candidates[0]
		return true, 0
	}

	return false, len(candidates)
}

// tryCalibrateInfoHashFromAPI discovers the info_hash offset by searching
// torrent dumps for known hashes from the qBittorrent sync API. Lock in when
// 2+ dumps agree on the same offset (each containing a different known hash).
//
// hashes are hex-encoded info_hashes (40 chars each). Returns (offset, true)
// when lock condition is met.
func (ts *torrentCalibrationState) tryCalibrateInfoHashFromAPI(dumps []bpf.CalibrationEvent, hashes []string) (offset int, numCandidates int, ok bool) {
	if ts.isInfoHashCalibrated() {
		return ts.infoHashOffset, 0, true
	}
	if len(hashes) == 0 {
		return -1, 0, false
	}

	// Build set of binary hashes (20 bytes each)
	hashSet := make(map[string]bool)
	for _, h := range hashes {
		if len(h) != 40 {
			continue
		}
		bin, err := hex.DecodeString(h)
		if err != nil || len(bin) != infoHashSize {
			continue
		}
		hashSet[string(bin)] = true
	}
	if len(hashSet) == 0 {
		return -1, 0, false
	}

	// Collect one dump per unique torrent_ptr
	byPtr := make(map[uint64]int)
	for i, d := range dumps {
		if _, exists := byPtr[d.ObjPtr]; !exists {
			byPtr[d.ObjPtr] = i
		}
	}
	if len(byPtr) == 0 {
		return -1, 0, false
	}

	// Scan every byte offset — the info_hash (SHA-1, 20 bytes) may not be
	// 8-byte aligned in the C++ struct. With API ground truth, false positives
	// are impossible (probability ~N/2^160), so byte-level scanning is safe.
	var candidates []int
	for off := 0; off <= calibrationDataSize-infoHashSize; off++ {
		seen := make(map[string]bool)
		valid := true
		for _, idx := range byPtr {
			chunk := dumps[idx].Data[off : off+infoHashSize]
			key := string(chunk)
			if !hashSet[key] {
				valid = false
				break
			}
			if seen[key] {
				valid = false
				break
			}
			seen[key] = true
		}
		if valid {
			candidates = append(candidates, off)
		}
	}

	if len(candidates) == 1 {
		return candidates[0], 1, true
	}
	return -1, len(candidates), false
}

// extractInfoHash reads the 20-byte info_hash from a torrent dump at the
// locked offset. Returns the raw binary hash and true if successful.
func (ts *torrentCalibrationState) extractInfoHash(data [calibrationDataSize]byte) ([]byte, bool) {
	if !ts.isInfoHashCalibrated() {
		return nil, false
	}
	if ts.infoHashOffset+infoHashSize > calibrationDataSize {
		return nil, false
	}
	raw := make([]byte, infoHashSize)
	copy(raw, data[ts.infoHashOffset:ts.infoHashOffset+infoHashSize])
	return raw, true
}

// tryCalibrateTorrentPtr scans a peer_connection dump for a known torrent*
// pointer value. knownTorrentPtrs is the set of torrent* pointers seen from
// we_have events.
// Returns true if the offset was locked in.
func (ts *torrentCalibrationState) tryCalibrateTorrentPtr(cal bpf.CalibrationEvent, knownTorrentPtrs map[uint64]bool) bool {
	if ts.isTorrentPtrCalibrated() {
		return true
	}

	if len(knownTorrentPtrs) == 0 {
		return false
	}

	// Scan the dump for 8-byte pointer values that match known torrent* ptrs.
	// Pointer alignment: check at 8-byte boundaries only (x86_64).
	for offset := 0; offset <= calibrationDataSize-8; offset += 8 {
		ptr := binary.LittleEndian.Uint64(cal.Data[offset : offset+8])
		if ptr == 0 {
			continue
		}
		if !knownTorrentPtrs[ptr] {
			continue
		}

		if ts.torrentPtrPtrs[offset] == nil {
			ts.torrentPtrPtrs[offset] = make(map[uint64]bool)
		}
		if ts.torrentPtrPtrs[offset][cal.ObjPtr] {
			continue
		}
		ts.torrentPtrPtrs[offset][cal.ObjPtr] = true

		ts.torrentPtrVotes[offset]++
		if ts.torrentPtrVotes[offset] >= torrentPtrMinVotes {
			ts.torrentPtrOffset = offset
			return true
		}
	}

	return false
}

// extractTorrentPtr reads the torrent* pointer from a peer_connection dump
// at the locked offset. Returns the pointer value and true if successful.
func (ts *torrentCalibrationState) extractTorrentPtr(data [calibrationDataSize]byte) (uint64, bool) {
	if !ts.isTorrentPtrCalibrated() {
		return 0, false
	}
	if ts.torrentPtrOffset+8 > calibrationDataSize {
		return 0, false
	}
	ptr := binary.LittleEndian.Uint64(data[ts.torrentPtrOffset : ts.torrentPtrOffset+8])
	return ptr, ptr != 0
}
