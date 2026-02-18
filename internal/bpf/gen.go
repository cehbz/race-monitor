package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel Probe probe.c -- -I./headers -D__TARGET_ARCH_x86

// Event mirrors the eBPF event_t struct layout (little-endian).
type Event struct {
	EventType  uint32
	PieceIndex uint32
	Timestamp  uint64
	ObjPtr     uint64
}

// CalibrationEvent mirrors the eBPF calibration_event_t struct layout.
// Emitted once per new peer_connection* to enable auto-discovery of the
// sockaddr_in offset within the peer_connection struct.
type CalibrationEvent struct {
	EventType uint32
	Pad       uint32 // alignment padding
	Timestamp uint64
	ObjPtr    uint64
	Data      [4096]byte
}

// Event type constants matching the eBPF #defines.
const (
	EventWeHave             uint32 = 1
	EventIncomingHave       uint32 = 2
	EventCalibration        uint32 = 3 // peer_connection struct dump
	EventTorrentCalibration uint32 = 4 // torrent struct dump (from we_have fallback)
	EventTorrentStarted     uint32 = 5 // torrent started (torrent struct dump from torrent::start)
	EventTorrentFinished    uint32 = 6 // torrent download completed (from torrent::finished)
)
