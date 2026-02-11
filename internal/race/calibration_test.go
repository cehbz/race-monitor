package race

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cehbz/race-monitor/internal/bpf"
)

// buildSockaddrIN writes a sockaddr_in at the given offset in a 512-byte buffer.
// sin_family=AF_INET(2) LE, sin_port=port BE, sin_addr=ip BE.
func buildSockaddrIN(buf *[512]byte, offset int, ip netip.Addr, port uint16) {
	binary.LittleEndian.PutUint16(buf[offset:], 2) // AF_INET
	binary.BigEndian.PutUint16(buf[offset+2:], port)
	ip4 := ip.As4()
	copy(buf[offset+4:], ip4[:])
}

func TestParseSockaddrIN_Valid(t *testing.T) {
	var buf [512]byte
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
	var buf [512]byte
	// Write AF_INET6 (10) instead of AF_INET (2)
	binary.LittleEndian.PutUint16(buf[100:], 10)

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected parse to fail for non-AF_INET family")
	}
}

func TestParseSockaddrIN_ZeroPort(t *testing.T) {
	var buf [512]byte
	binary.LittleEndian.PutUint16(buf[100:], 2) // AF_INET
	// Port is 0 — should reject

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected parse to fail for zero port")
	}
}

func TestParseSockaddrIN_LoopbackRejected(t *testing.T) {
	var buf [512]byte
	ip := netip.MustParseAddr("127.0.0.1")
	buildSockaddrIN(&buf, 100, ip, 6881)

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected loopback address to be rejected")
	}
}

func TestParseSockaddrIN_UnspecifiedRejected(t *testing.T) {
	var buf [512]byte
	ip := netip.MustParseAddr("0.0.0.0")
	buildSockaddrIN(&buf, 100, ip, 6881)

	_, ok := parseSockaddrIN(buf[:], 100)
	if ok {
		t.Error("expected unspecified address to be rejected")
	}
}

func TestParseSockaddrIN_OutOfBounds(t *testing.T) {
	var buf [512]byte
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
	var data1 [512]byte
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
	var data2 [512]byte
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

	var data [512]byte
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

	var data [512]byte
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
	var data [512]byte
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

	var data [512]byte
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

	var data [512]byte
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
	var d1, d2, d3 [512]byte
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
	var d1, d2, d3 [512]byte
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

// writePeerID writes a BT peer_id at the given offset in a 512-byte buffer.
func writePeerID(buf *[512]byte, offset int, peerID string) {
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
	var d1 [512]byte
	buildSockaddrIN(&d1, 64, ip1, 6881)
	writePeerID(&d1, 256, "-qB4530-aaaaaaaaaaaa")
	cal1 := bpf.CalibrationEvent{ObjPtr: 0x1000, Data: d1}

	if cs.tryCalibratePeerID(cal1, knownPeerIDs) {
		t.Fatal("should not lock in after 1 vote")
	}

	// Second event: different peer, peer_id at same offset 256
	var d2 [512]byte
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

	var d [512]byte
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

	var d [512]byte
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

	var d [512]byte
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

	var d [512]byte
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
