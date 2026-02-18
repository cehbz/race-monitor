package race

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cehbz/race-monitor/internal/bpf"
)

// buildSockaddrIN writes a sockaddr_in at the given offset in a calibration buffer.
// sin_family=AF_INET(2) LE, sin_port=port BE, sin_addr=ip BE.
func buildSockaddrIN(buf *[calibrationDataSize]byte, offset int, ip netip.Addr, port uint16) {
	binary.LittleEndian.PutUint16(buf[offset:], 2) // AF_INET
	binary.BigEndian.PutUint16(buf[offset+2:], port)
	ip4 := ip.As4()
	copy(buf[offset+4:], ip4[:])
}

func TestParseSockaddrIN_Valid(t *testing.T) {
	var buf [calibrationDataSize]byte
	ip := netip.MustParseAddr("192.168.1.10")
	buildSockaddrIN(&buf, 100, ip, 6881)

	addr, ok := parseSockaddrIN(buf[:], 100)
	if !ok {
		t.Fatal("expected valid sockaddr_in parse")
	}
	if addr.Addr() != ip {
		t.Errorf("expected IP %s, got %s", ip, addr.Addr())
	}
	if addr.Port() != 6881 {
		t.Errorf("expected port 6881, got %d", addr.Port())
	}
}

func TestParseSockaddrIN_WrongFamily(t *testing.T) {
	var buf [calibrationDataSize]byte
	// Write AF_INET6 (10) instead of AF_INET (2)
	binary.LittleEndian.PutUint16(buf[100:], 10)

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected parse to fail for non-AF_INET family")
	}
}

func TestParseSockaddrIN_ZeroPort(t *testing.T) {
	var buf [calibrationDataSize]byte
	binary.LittleEndian.PutUint16(buf[100:], 2) // AF_INET
	// Port is 0 — should reject

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected parse to fail for zero port")
	}
}

func TestParseSockaddrIN_LoopbackRejected(t *testing.T) {
	var buf [calibrationDataSize]byte
	ip := netip.MustParseAddr("127.0.0.1")
	buildSockaddrIN(&buf, 100, ip, 6881)

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected loopback address to be rejected")
	}
}

func TestParseSockaddrIN_UnspecifiedRejected(t *testing.T) {
	var buf [calibrationDataSize]byte
	ip := netip.MustParseAddr("0.0.0.0")
	buildSockaddrIN(&buf, 100, ip, 6881)

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected unspecified address to be rejected")
	}
}

func TestParseSockaddrIN_OutOfBounds(t *testing.T) {
	var buf [calibrationDataSize]byte
	// Offset too close to end — not enough room for 8 bytes
	_, ok := parseSockaddrIN(buf[:], 510)
	if ok {
		t.Error("expected parse to fail for out-of-bounds offset")
	}
}

func TestCalibrationState_TwoVotesLockIn(t *testing.T) {
	cs := newCalibrationState()

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")
	known := map[netip.AddrPort]bool{
		netip.AddrPortFrom(ip1, 6881): true,
		netip.AddrPortFrom(ip2, 6881): true,
	}

	// First calibration event: peer_connection* = 0x1000 with IP at offset 64
	var data1 [calibrationDataSize]byte
	buildSockaddrIN(&data1, 64, ip1, 6881)
	cal1 := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: data1}

	// First event — should not lock in (need ≥2 votes)
	if cs.tryCalibrate(cal1, known) {
		t.Fatal("expected calibration to NOT lock in after 1 vote")
	}
	if cs.isCalibrated() {
		t.Fatal("should not be calibrated yet")
	}

	// Second calibration event: different ptr, same offset
	var data2 [calibrationDataSize]byte
	buildSockaddrIN(&data2, 64, ip2, 6881)
	cal2 := bpf.CalibrationEvent{ObjPtr: 0x2000, Data: data2}

	if !cs.tryCalibrate(cal2, known) {
		t.Fatal("expected calibration to lock in after 2 votes")
	}
	if !cs.isCalibrated() {
		t.Fatal("should be calibrated")
	}
	if cs.offset != 64 {
		t.Errorf("expected offset 64, got %d", cs.offset)
	}
}

func TestCalibrationState_NoDuplicateVotesFromSamePtr(t *testing.T) {
	cs := newCalibrationState()

	ip := netip.MustParseAddr("10.0.0.1")
	known := map[netip.AddrPort]bool{
		netip.AddrPortFrom(ip, 6881): true,
	}

	var data [calibrationDataSize]byte
	buildSockaddrIN(&data, 64, ip, 6881)
	cal := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: data}

	// Same ptr twice — should not double-count
	cs.tryCalibrate(cal, known)
	cs.tryCalibrate(cal, known)

	if cs.isCalibrated() {
		t.Error("same ptr should not vote twice at the same offset")
	}
	if cs.votes[64] != 1 {
		t.Errorf("expected 1 vote at offset 64, got %d", cs.votes[64])
	}
}

func TestCalibrationState_NoMatchWithoutKnownPeers(t *testing.T) {
	cs := newCalibrationState()
	known := map[netip.AddrPort]bool{} // empty

	var data [calibrationDataSize]byte
	buildSockaddrIN(&data, 64, netip.MustParseAddr("10.0.0.1"), 6881)
	cal := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: data}

	if cs.tryCalibrate(cal, known) {
		t.Error("should not calibrate with empty known peers")
	}
}

func TestCalibrationState_NoMatchForUnknownIP(t *testing.T) {
	cs := newCalibrationState()
	known := map[netip.AddrPort]bool{
		netip.MustParseAddrPort("192.168.1.1:6881"): true,
	}

	// Data has a different IP than the known set
	var data [calibrationDataSize]byte
	buildSockaddrIN(&data, 64, netip.MustParseAddr("10.0.0.99"), 6881)
	cal := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: data}

	if cs.tryCalibrate(cal, known) {
		t.Error("should not calibrate when IP doesn't match known peers")
	}
	if cs.votes[64] != 0 {
		t.Error("should not have any votes")
	}
}

func TestCalibrationState_ExtractEndpoint(t *testing.T) {
	cs := newCalibrationState()
	cs.offset = 64 // Manually set calibrated offset

	var data [calibrationDataSize]byte
	buildSockaddrIN(&data, 64, netip.MustParseAddr("172.16.0.5"), 51413)

	addr, ok := cs.extractEndpoint(data)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if addr.Addr().String() != "172.16.0.5" {
		t.Errorf("expected 172.16.0.5, got %s", addr.Addr())
	}
	if addr.Port() != 51413 {
		t.Errorf("expected port 51413, got %d", addr.Port())
	}
}

func TestCalibrationState_ExtractFailsWhenUncalibrated(t *testing.T) {
	cs := newCalibrationState()

	var data [calibrationDataSize]byte
	buildSockaddrIN(&data, 64, netip.MustParseAddr("172.16.0.5"), 51413)

	_, ok := cs.extractEndpoint(data)
	if ok {
		t.Error("extraction should fail when not calibrated")
	}
}

func TestCalibrationState_MultipleOffsetsVoting(t *testing.T) {
	cs := newCalibrationState()

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")
	ip3 := netip.MustParseAddr("10.0.0.3")
	known := map[netip.AddrPort]bool{
		netip.AddrPortFrom(ip1, 6881): true,
		netip.AddrPortFrom(ip2, 6881): true,
		netip.AddrPortFrom(ip3, 6881): true,
	}

	// Two events with sockaddr at offset 64, one at offset 128
	var d1, d2, d3 [calibrationDataSize]byte
	buildSockaddrIN(&d1, 64, ip1, 6881)
	buildSockaddrIN(&d2, 128, ip2, 6881) // red herring at different offset
	buildSockaddrIN(&d3, 64, ip3, 6881)

	cs.tryCalibrate(bpf.CalibrationEvent{ObjPtr: 0x1000, Data: d1}, known)
	cs.tryCalibrate(bpf.CalibrationEvent{ObjPtr: 0x2000, Data: d2}, known)

	// After 2 events, offset 64 has 1 vote, offset 128 has 1 vote — not calibrated
	if cs.isCalibrated() {
		t.Fatal("should not be calibrated after 1 vote per offset")
	}

	// Third event at offset 64 gives it 2 votes → locks in
	if !cs.tryCalibrate(bpf.CalibrationEvent{ObjPtr: 0x3000, Data: d3}, known) {
		t.Fatal("expected offset 64 to lock in with 2 votes")
	}
	if cs.offset != 64 {
		t.Errorf("expected offset 64, got %d", cs.offset)
	}
}

func TestCalibrationState_PendingReprocessing(t *testing.T) {
	cs := newCalibrationState()

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")
	ip3 := netip.MustParseAddr("10.0.0.3")
	known := map[netip.AddrPort]bool{
		netip.AddrPortFrom(ip1, 6881): true,
		netip.AddrPortFrom(ip2, 6881): true,
		netip.AddrPortFrom(ip3, 6881): true,
	}

	// Buffer 3 events (simulating they arrived before known peers)
	var d1, d2, d3 [calibrationDataSize]byte
	buildSockaddrIN(&d1, 200, ip1, 6881)
	buildSockaddrIN(&d2, 200, ip2, 6881)
	buildSockaddrIN(&d3, 200, ip3, 6881)

	cs.pending = []bpf.CalibrationEvent{
		{ObjPtr: 0x1000, Data: d1},
		{ObjPtr: 0x2000, Data: d2},
		{ObjPtr: 0x3000, Data: d3},
	}

	// Process pending — should discover offset 200 after 2 matches
	for _, cal := range cs.pending {
		if cs.tryCalibrate(cal, known) {
			break
		}
	}

	if !cs.isCalibrated() {
		t.Fatal("expected calibration from pending events")
	}
	if cs.offset != 200 {
		t.Errorf("expected offset 200, got %d", cs.offset)
	}

	// Extract from remaining pending events
	addr, ok := cs.extractEndpoint(d3)
	if !ok {
		t.Fatal("expected successful extraction from pending event data")
	}
	if addr.Addr() != ip3 {
		t.Errorf("expected %s, got %s", ip3, addr.Addr())
	}
}

// --- Peer ID calibration tests ---

// writePeerID writes a BT peer_id at the given offset in a calibration buffer.
func writePeerID(buf *[calibrationDataSize]byte, offset int, peerID string) {
	copy(buf[offset:], []byte(peerID))
}

func TestCalibratePeerID_TwoVotesLockIn(t *testing.T) {
	cs := newCalibrationState()
	cs.offset = 64 // sockaddr_in already calibrated

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")

	// Known peer_ids from API, keyed by IP:port
	knownPeerIDs := map[netip.AddrPort]string{
		netip.AddrPortFrom(ip1, 6881): "-qB4530-aaaaaaaaaaaa",
		netip.AddrPortFrom(ip2, 6881): "-DE2110-bbbbbbbbbbbb",
	}

	// First event: peer with IP 10.0.0.1, peer_id at offset 256
	var d1 [calibrationDataSize]byte
	buildSockaddrIN(&d1, 64, ip1, 6881)
	writePeerID(&d1, 256, "-qB4530-aaaaaaaaaaaa")
	cal1 := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: d1}

	if cs.tryCalibratePeerID(cal1, knownPeerIDs) {
		t.Fatal("should not lock in after 1 vote")
	}

	// Second event: different peer, peer_id at same offset 256
	var d2 [calibrationDataSize]byte
	buildSockaddrIN(&d2, 64, ip2, 6881)
	writePeerID(&d2, 256, "-DE2110-bbbbbbbbbbbb")
	cal2 := bpf.CalibrationEvent{ObjPtr: 0x2000, Data: d2}

	if !cs.tryCalibratePeerID(cal2, knownPeerIDs) {
		t.Fatal("expected peer_id calibration to lock in after 2 votes")
	}
	if cs.peerIDOffset != 256 {
		t.Errorf("expected peer_id offset 256, got %d", cs.peerIDOffset)
	}
	if !cs.isFullyCalibrated() {
		t.Error("should be fully calibrated")
	}
}

func TestCalibratePeerID_RequiresSockaddrFirst(t *testing.T) {
	cs := newCalibrationState()
	// sockaddr_in NOT calibrated

	knownPeerIDs := map[netip.AddrPort]string{
		netip.MustParseAddrPort("10.0.0.1:6881"): "-qB4530-aaaaaaaaaaaa",
	}

	var d [calibrationDataSize]byte
	cal := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: d}

	if cs.tryCalibratePeerID(cal, knownPeerIDs) {
		t.Error("should not calibrate peer_id without sockaddr_in")
	}
}

func TestCalibratePeerID_NoDuplicateVotes(t *testing.T) {
	cs := newCalibrationState()
	cs.offset = 64

	ip := netip.MustParseAddr("10.0.0.1")
	knownPeerIDs := map[netip.AddrPort]string{
		netip.AddrPortFrom(ip, 6881): "-qB4530-aaaaaaaaaaaa",
	}

	var d [calibrationDataSize]byte
	buildSockaddrIN(&d, 64, ip, 6881)
	writePeerID(&d, 256, "-qB4530-aaaaaaaaaaaa")
	cal := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: d}

	cs.tryCalibratePeerID(cal, knownPeerIDs)
	cs.tryCalibratePeerID(cal, knownPeerIDs) // same ptr

	if cs.peerIDOffset >= 0 {
		t.Error("same ptr should not vote twice")
	}
	if cs.peerIDVotes[256] != 1 {
		t.Errorf("expected 1 vote at offset 256, got %d", cs.peerIDVotes[256])
	}
}

func TestExtractPeerID(t *testing.T) {
	cs := newCalibrationState()
	cs.offset = 64
	cs.peerIDOffset = 256

	var d [calibrationDataSize]byte
	writePeerID(&d, 256, "-qB4530-aaaaaaaaaaaa")

	peerID, ok := cs.extractPeerID(d)
	if !ok {
		t.Fatal("expected successful peer_id extraction")
	}
	if peerID != "-qB4530-aaaaaaaaaaaa" {
		t.Errorf("expected '-qB4530-aaaaaaaaaaaa', got %q", peerID)
	}
}

func TestExtractPeerID_FailsWhenUncalibrated(t *testing.T) {
	cs := newCalibrationState()

	var d [calibrationDataSize]byte
	_, ok := cs.extractPeerID(d)
	if ok {
		t.Error("extraction should fail when peer_id not calibrated")
	}
}

func TestDecodePeerClient(t *testing.T) {
	tests := []struct {
		peerID string
		want   string
	}{
		{"-qB4530-aaaaaaaaaaaa", "qBittorrent 4530"},
		{"-DE2110-bbbbbbbbbbbb", "Deluge 2110"},
		{"-TR3040-cccccccccccc", "Transmission 3040"},
		{"-UT3456-dddddddddddd", "uTorrent 3456"},
		{"short", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := decodePeerClient(tt.peerID)
		if got != tt.want {
			t.Errorf("decodePeerClient(%q) = %q, want %q", tt.peerID, got, tt.want)
		}
	}
}

func TestNewCalibratedState(t *testing.T) {
	cs := newCalibratedState(64, 256)
	if !cs.isCalibrated() {
		t.Error("expected sockaddr_in calibrated")
	}
	if !cs.isFullyCalibrated() {
		t.Error("expected fully calibrated")
	}
	if cs.offset != 64 {
		t.Errorf("expected sockaddr offset 64, got %d", cs.offset)
	}
	if cs.peerIDOffset != 256 {
		t.Errorf("expected peer_id offset 256, got %d", cs.peerIDOffset)
	}
}

// --- Torrent calibration tests ---

// writeInfoHash places a 20-byte info_hash at the given offset in a calibration buffer.
func writeInfoHash(buf *[calibrationDataSize]byte, offset int, hash []byte) {
	copy(buf[offset:offset+20], hash)
}

// writeTorrentPtr places a 64-bit pointer at the given offset (8-byte aligned) in a buffer.
func writeTorrentPtr(buf *[calibrationDataSize]byte, offset int, ptr uint64) {
	binary.LittleEndian.PutUint64(buf[offset:], ptr)
}

func TestTorrentCalibration_CorrelationTwoDumps(t *testing.T) {
	ts := newTorrentCalibrationState()

	hash1 := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	hash2 := []byte{0xca, 0xfe, 0xba, 0xbe, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	var d1, d2 [calibrationDataSize]byte
	writeInfoHash(&d1, 128, hash1)
	writeInfoHash(&d2, 128, hash2)

	dumps := []bpf.CalibrationEvent{
		{ObjPtr: 0x5000, Data: d1},
		{ObjPtr: 0x6000, Data: d2},
	}

	// With only 2 dumps, correlation may or may not lock in depending on
	// how many other offsets also have unique values. Try it — if it locks,
	// it should be at offset 128.
	locked, _ := ts.tryCalibrateInfoHashByCorrelation(dumps)
	if locked {
		if ts.infoHashOffset != 128 {
			t.Errorf("expected offset 128, got %d", ts.infoHashOffset)
		}
	}
	// If not locked with 2 dumps, that's acceptable — add a 3rd dump
}

func TestTorrentCalibration_CorrelationThreeDumps(t *testing.T) {
	ts := newTorrentCalibrationState()

	// Hash at offset 488 so overlapping windows at 480, 472, etc. are rejected.
	// hash1 and hash2 share first 12 bytes so offset 480 (8 zeros + hash[0:12])
	// has duplicate → rejected. Only offset 488 has all 3 unique.
	hash1 := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	hash2 := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}
	hash3 := []byte{0x42, 0x43, 0x44, 0x45, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

	const infoHashOffset = 488
	var d1, d2, d3 [calibrationDataSize]byte
	writeInfoHash(&d1, infoHashOffset, hash1)
	writeInfoHash(&d2, infoHashOffset, hash2)
	writeInfoHash(&d3, infoHashOffset, hash3)

	dumps := []bpf.CalibrationEvent{
		{ObjPtr: 0x5000, Data: d1},
		{ObjPtr: 0x6000, Data: d2},
		{ObjPtr: 0x7000, Data: d3},
	}

	locked, _ := ts.tryCalibrateInfoHashByCorrelation(dumps)
	if !locked {
		t.Fatal("expected correlation to lock in with 3 diverse dumps")
	}
	if ts.infoHashOffset != infoHashOffset {
		t.Errorf("expected offset %d, got %d", infoHashOffset, ts.infoHashOffset)
	}
}

func TestTorrentCalibration_CorrelationNeedsTwoPtrs(t *testing.T) {
	ts := newTorrentCalibrationState()

	hash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	var d [calibrationDataSize]byte
	writeInfoHash(&d, 128, hash)

	// Single dump — should not calibrate
	dumps := []bpf.CalibrationEvent{
		{ObjPtr: 0x5000, Data: d},
	}

	locked, _ := ts.tryCalibrateInfoHashByCorrelation(dumps)
	if locked {
		t.Error("should not calibrate with only 1 dump")
	}
}

func TestTorrentCalibration_CorrelationAlreadyCalibrated(t *testing.T) {
	ts := newTorrentCalibrationState()
	ts.infoHashOffset = 128 // pre-set

	locked, _ := ts.tryCalibrateInfoHashByCorrelation(nil)
	if !locked {
		t.Error("should return true when already calibrated")
	}
}

func TestTorrentCalibration_FromAPI(t *testing.T) {
	ts := newTorrentCalibrationState()

	hash1 := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	hash2 := []byte{0x42, 0x43, 0x44, 0x45, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

	const infoHashOffset = 256
	var d1, d2 [calibrationDataSize]byte
	writeInfoHash(&d1, infoHashOffset, hash1)
	writeInfoHash(&d2, infoHashOffset, hash2)

	dumps := []bpf.CalibrationEvent{
		{ObjPtr: 0x5000, Data: d1},
		{ObjPtr: 0x6000, Data: d2},
	}

	hashes := []string{
		"deadbeef01020304050607081112131415161718",
		"424344453132333435363738393a3b3c3d3e3f40",
	}

	off, _, ok := ts.tryCalibrateInfoHashFromAPI(dumps, hashes)
	if !ok {
		t.Fatal("expected API calibration to lock in with 2 dumps and matching hashes")
	}
	if off != infoHashOffset {
		t.Errorf("expected offset %d, got %d", infoHashOffset, off)
	}
}

func TestTorrentCalibration_FromAPISingleDump(t *testing.T) {
	ts := newTorrentCalibrationState()

	hash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	var d [calibrationDataSize]byte
	writeInfoHash(&d, 128, hash)

	dumps := []bpf.CalibrationEvent{{ObjPtr: 0x5000, Data: d}}
	hashes := []string{"deadbeef0102030405060708090a0b0c0d0e0f10"}

	off, _, ok := ts.tryCalibrateInfoHashFromAPI(dumps, hashes)
	if !ok {
		t.Fatal("expected API calibration to lock in with 1 dump and matching hash")
	}
	if off != 128 {
		t.Errorf("expected offset 128, got %d", off)
	}
}

func TestTorrentCalibration_ExtractInfoHash(t *testing.T) {
	ts := newTorrentCalibrationState()
	ts.infoHashOffset = 128

	hash := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xab, 0xcd, 0xef, 0x01}
	var data [calibrationDataSize]byte
	writeInfoHash(&data, 128, hash)

	extracted, ok := ts.extractInfoHash(data)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	for i := range hash {
		if extracted[i] != hash[i] {
			t.Fatalf("mismatch at byte %d: got %02x, want %02x", i, extracted[i], hash[i])
		}
	}
}

func TestTorrentCalibration_ExtractInfoHashFailsUncalibrated(t *testing.T) {
	ts := newTorrentCalibrationState()
	var data [calibrationDataSize]byte
	_, ok := ts.extractInfoHash(data)
	if ok {
		t.Error("should fail when not calibrated")
	}
}

func TestTorrentCalibration_TorrentPtrTwoVotesLockIn(t *testing.T) {
	ts := newTorrentCalibrationState()

	knownPtrs := map[uint64]bool{
		0xffff_0000_1111_2222: true,
		0xffff_0000_3333_4444: true,
	}

	// First peer_connection dump with known torrent ptr at offset 48
	var d1 [calibrationDataSize]byte
	writeTorrentPtr(&d1, 48, 0xffff_0000_1111_2222)
	cal1 := bpf.CalibrationEvent{ObjPtr: 0xa000, Data: d1}

	if ts.tryCalibrateTorrentPtr(cal1, knownPtrs) {
		t.Fatal("should not lock in after 1 vote")
	}

	// Second dump from different peer_connection, same offset
	var d2 [calibrationDataSize]byte
	writeTorrentPtr(&d2, 48, 0xffff_0000_3333_4444)
	cal2 := bpf.CalibrationEvent{ObjPtr: 0xb000, Data: d2}

	if !ts.tryCalibrateTorrentPtr(cal2, knownPtrs) {
		t.Fatal("expected torrent_ptr calibration to lock in after 2 votes")
	}
	if ts.torrentPtrOffset != 48 {
		t.Errorf("expected offset 48, got %d", ts.torrentPtrOffset)
	}
}

func TestTorrentCalibration_TorrentPtrNoDuplicateVotes(t *testing.T) {
	ts := newTorrentCalibrationState()

	knownPtrs := map[uint64]bool{0xffff_0000_1111_2222: true}

	var d [calibrationDataSize]byte
	writeTorrentPtr(&d, 48, 0xffff_0000_1111_2222)
	cal := bpf.CalibrationEvent{ObjPtr: 0xa000, Data: d}

	ts.tryCalibrateTorrentPtr(cal, knownPtrs)
	ts.tryCalibrateTorrentPtr(cal, knownPtrs)

	if ts.isTorrentPtrCalibrated() {
		t.Error("same ptr should not vote twice")
	}
	if ts.torrentPtrVotes[48] != 1 {
		t.Errorf("expected 1 vote, got %d", ts.torrentPtrVotes[48])
	}
}

func TestTorrentCalibration_TorrentPtrNoKnownPtrs(t *testing.T) {
	ts := newTorrentCalibrationState()

	var d [calibrationDataSize]byte
	cal := bpf.CalibrationEvent{ObjPtr: 0xa000, Data: d}

	if ts.tryCalibrateTorrentPtr(cal, nil) {
		t.Error("should not calibrate with no known pointers")
	}
}

func TestTorrentCalibration_ExtractTorrentPtr(t *testing.T) {
	ts := newTorrentCalibrationState()
	ts.torrentPtrOffset = 48

	var d [calibrationDataSize]byte
	writeTorrentPtr(&d, 48, 0xdeadbeef_cafebabe)

	ptr, ok := ts.extractTorrentPtr(d)
	if !ok {
		t.Fatal("expected successful extraction")
	}
	if ptr != 0xdeadbeef_cafebabe {
		t.Errorf("expected 0xdeadbeefcafebabe, got 0x%x", ptr)
	}
}

func TestTorrentCalibration_ExtractTorrentPtrFailsUncalibrated(t *testing.T) {
	ts := newTorrentCalibrationState()
	var d [calibrationDataSize]byte
	_, ok := ts.extractTorrentPtr(d)
	if ok {
		t.Error("should fail when not calibrated")
	}
}
