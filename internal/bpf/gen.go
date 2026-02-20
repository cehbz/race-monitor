package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel Probe probe.c -- -I./headers -D__TARGET_ARCH_x86

// Event mirrors the eBPF event_t struct layout (little-endian).
type Event struct {
	EventType  uint32
	PieceIndex uint32
	Timestamp  uint64
	ObjPtr     uint64
}

// DumpEvent mirrors the eBPF struct_dump_t layout.
// Carries a raw memory dump from a libtorrent object (peer_connection or torrent).
// Emitted once per unique pointer for peer/torrent identification in userspace.
type DumpEvent struct {
	EventType uint32
	Pad       uint32 // alignment padding
	Timestamp uint64
	ObjPtr    uint64
	Data      [4096]byte
}

// Event type constants matching the eBPF #defines.
const (
	EventWeHave          uint32 = 1
	EventIncomingHave    uint32 = 2
	EventPeerDump        uint32 = 3 // peer_connection struct dump
	EventTorrentDump     uint32 = 4 // torrent struct dump (from we_have first encounter)
	EventTorrentStarted  uint32 = 5 // torrent started (torrent struct dump from torrent::start)
	EventTorrentFinished uint32 = 6 // torrent download completed (from torrent::finished)
)
