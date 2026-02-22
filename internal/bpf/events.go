package bpf

// ProbeEvent is a sealed interface for typed eBPF probe events.
// Each concrete type carries context-specific field names instead of
// a generic ObjPtr + EventType discriminant.
type ProbeEvent interface {
	probeEvent() // sealed marker
}

// WeHaveEvent fires when we complete and verify a piece (torrent::we_have).
type WeHaveEvent struct {
	TorrentPtr uint64
	PieceIndex uint32
	Timestamp  uint64
}

// IncomingHaveEvent fires when a peer announces a piece via HAVE message.
type IncomingHaveEvent struct {
	ConnPtr    uint64 // peer_connection*
	PieceIndex uint32
	Timestamp  uint64
}

// TorrentFinishedEvent fires when all pieces are downloaded and verified.
type TorrentFinishedEvent struct {
	TorrentPtr uint64
	Timestamp  uint64
}

// PeerDetailsEvent carries a 4KB peer_connection struct dump for identity extraction.
type PeerDetailsEvent struct {
	ConnPtr   uint64 // peer_connection*
	Timestamp uint64
	Data      [4096]byte
}

// TorrentDetailsEvent carries a 4KB torrent struct dump from we_have first encounter.
type TorrentDetailsEvent struct {
	TorrentPtr uint64
	Timestamp  uint64
	Data       [4096]byte
}

// TorrentStartedEvent fires when torrent::start() is called, carrying a struct dump.
type TorrentStartedEvent struct {
	TorrentPtr uint64
	Timestamp  uint64
	Data       [4096]byte
}

func (*WeHaveEvent) probeEvent()          {}
func (*IncomingHaveEvent) probeEvent()    {}
func (*TorrentFinishedEvent) probeEvent() {}
func (*PeerDetailsEvent) probeEvent()     {}
func (*TorrentDetailsEvent) probeEvent()  {}
func (*TorrentStartedEvent) probeEvent()  {}
