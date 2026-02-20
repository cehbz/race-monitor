//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define EVT_WE_HAVE              1
#define EVT_INCOMING_HAVE         2
#define EVT_PEER_DUMP             3
#define EVT_TORRENT_DUMP          4
#define EVT_TORRENT_STARTED       5
#define EVT_TORRENT_FINISHED      6

#define DUMP_READ_SIZE 4096

// event_t is the perf event structure emitted to userspace.
// Zero struct offset reads — we only capture function arguments and the this pointer.
struct event_t {
	u32 event_type;
	u32 piece_index;
	u64 timestamp;
	u64 obj_ptr;  // this pointer: torrent* for we_have, peer_connection* for incoming_have
};

// struct_dump_t carries a raw memory dump from a libtorrent object.
// Emitted once per unique pointer for peer/torrent identification in userspace.
struct struct_dump_t {
	u32 event_type;
	u32 _pad;        // alignment padding
	u64 timestamp;
	u64 obj_ptr;     // peer_connection* or torrent*
	u8  data[DUMP_READ_SIZE];
};

// probe_config carries calibrated offsets from userspace. Written once by the
// monitor after loading BPF objects. When torrent_ptr_offset == 0, probes fall
// back to pointer-based dedup (calibration mode).
struct probe_config {
	u32 torrent_ptr_offset;  // offset of torrent* within peer_connection struct
	u32 sockaddr_offset;     // offset of sockaddr_in within peer_connection struct
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct probe_config);
} probe_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// peer_key identifies a peer connection by its actual identity rather than
// its memory address. This prevents cross-race contamination when libtorrent
// frees a peer_connection and reuses the address for a different torrent.
struct peer_key {
	u64 torrent_ptr;  // torrent* this peer belongs to
	u32 ip;           // sin_addr.s_addr (raw network byte order)
	u16 port;         // sin_port (raw network byte order)
	u16 _pad;
};

// seen_peers tracks peer connections we've already emitted a struct dump for.
// Key is identity-based (torrent, IP, port) when calibrated offsets are
// available, or pointer-based when in calibration mode.
// LRU eviction prevents leaks in long-running daemons.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct peer_key);
	__type(value, u8);
} seen_peers SEC(".maps");

// Per-CPU scratch space for struct_dump_t to avoid exceeding the BPF
// stack limit. Each CPU gets its own copy, so no locking needed.
// Shared by both peer_connection and torrent dump events (serialized per-CPU).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct struct_dump_t);
} dump_scratch SEC(".maps");

// seen_torrents tracks torrent* pointers we've already emitted a
// struct dump for. Used to emit one dump per unique torrent.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, u64);
	__type(value, u8);
} seen_torrents SEC(".maps");

// emit_peer_dump_if_new checks the seen_peers dedup map and emits a
// peer_connection struct dump if this peer hasn't been seen before.
// Returns 1 if a dump was emitted, 0 otherwise.
//
// When calibrated offsets are available (monitor mode), the dedup key is
// (torrent_ptr, IP, port) — the actual peer identity. When offsets are
// unknown (calibration mode), falls back to the raw pointer value.
static __always_inline int emit_peer_dump_if_new(struct pt_regs *ctx, u64 ptr) {
	struct peer_key key = {};
	u32 cfg_key = 0;
	struct probe_config *cfg = bpf_map_lookup_elem(&probe_config, &cfg_key);

	if (cfg && cfg->torrent_ptr_offset != 0) {
		// Monitor mode: dedup by (torrent_ptr, ip, port)
		bpf_probe_read_user(&key.torrent_ptr, sizeof(key.torrent_ptr),
		                    (void *)(ptr + cfg->torrent_ptr_offset));
		bpf_probe_read_user(&key.ip, sizeof(key.ip),
		                    (void *)(ptr + cfg->sockaddr_offset + 4));
		bpf_probe_read_user(&key.port, sizeof(key.port),
		                    (void *)(ptr + cfg->sockaddr_offset + 2));
	} else {
		// Calibration mode: offsets unknown, fall back to pointer-based dedup
		key.torrent_ptr = ptr;
	}

	u8 *seen = bpf_map_lookup_elem(&seen_peers, &key);
	if (seen)
		return 0;

	u8 one = 1;
	bpf_map_update_elem(&seen_peers, &key, &one, BPF_ANY);

	u32 scratch_key = 0;
	struct struct_dump_t *dump = bpf_map_lookup_elem(&dump_scratch, &scratch_key);
	if (!dump)
		return 0;

	dump->event_type = EVT_PEER_DUMP;
	dump->_pad = 0;
	dump->timestamp = bpf_ktime_get_ns();
	dump->obj_ptr = ptr;

	bpf_probe_read_user(dump->data, DUMP_READ_SIZE, (void *)ptr);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dump, sizeof(*dump));
	return 1;
}

// trace_we_have hooks libtorrent::torrent::we_have(piece_index_t).
// Called once per completed+verified piece. Very low frequency (~1K/race).
// x86_64 ABI: RDI = this (torrent*), RSI = piece_index (strong_typedef<int> passed as int).
//
// On first encounter of each torrent*, emits a torrent struct dump
// for userspace to extract the info_hash from.
SEC("uprobe/we_have")
int trace_we_have(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);

	// Emit torrent struct dump on first encounter of this torrent*
	u8 *seen = bpf_map_lookup_elem(&seen_torrents, &ptr);
	if (!seen) {
		u8 one = 1;
		bpf_map_update_elem(&seen_torrents, &ptr, &one, BPF_ANY);

		u32 key = 0;
		struct struct_dump_t *dump = bpf_map_lookup_elem(&dump_scratch, &key);
		if (dump) {
			dump->event_type = EVT_TORRENT_DUMP;
			dump->_pad = 0;
			dump->timestamp = bpf_ktime_get_ns();
			dump->obj_ptr = ptr;

			bpf_probe_read_user(dump->data, DUMP_READ_SIZE, (void *)ptr);
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dump, sizeof(*dump));
		}
	}

	// Always emit the normal we_have event
	struct event_t event = {};
	event.event_type = EVT_WE_HAVE;
	event.obj_ptr = ptr;
	event.piece_index = (u32)PT_REGS_PARM2(ctx);
	event.timestamp = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

// trace_incoming_have hooks libtorrent::peer_connection::incoming_have(piece_index_t).
// Called when a peer announces it has a piece. Moderate frequency (~3K/sec peak).
// x86_64 ABI: RDI = this (peer_connection*), RSI = piece_index.
//
// On first encounter of each peer connection identity, emits a struct dump for
// userspace to extract sockaddr_in, peer_id, and torrent_ptr from.
SEC("uprobe/incoming_have")
int trace_incoming_have(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);

	// Emit struct dump on first encounter of this peer identity
	emit_peer_dump_if_new(ctx, ptr);

	// Always emit the normal incoming_have event
	struct event_t event = {};
	event.event_type = EVT_INCOMING_HAVE;
	event.obj_ptr = ptr;
	event.piece_index = (u32)PT_REGS_PARM2(ctx);
	event.timestamp = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

// trace_incoming_piece hooks libtorrent::peer_connection::incoming_piece().
// Called when we receive a piece fragment from a peer during active download.
// Unlike incoming_have (which only fires when peers announce new pieces),
// incoming_piece fires for every piece transfer — critical for peer discovery
// when the swarm is dominated by seeders who never send HAVE messages.
//
// Uses the same seen_peers dedup map as incoming_have.
// x86_64 ABI: RDI = this (peer_connection*).
SEC("uprobe/incoming_piece")
int trace_incoming_piece(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);

	// Emit struct dump on first encounter of this peer identity
	emit_peer_dump_if_new(ctx, ptr);

	// No slim event emitted — incoming_piece is only used for peer discovery.
	// The piece data is tracked via we_have (after verification).
	return 0;
}

// trace_incoming_bitfield hooks libtorrent::peer_connection::incoming_bitfield().
// Called when a peer sends a BITFIELD message at connect time, announcing all
// pieces they already have. Seeders use BITFIELD (or HAVE-ALL) instead of
// individual HAVE messages, so incoming_have never fires for them. This probe
// ensures we discover every peer_connection* including seeders.
//
// Uses the same seen_peers dedup map as incoming_have and incoming_piece.
// x86_64 ABI: RDI = this (peer_connection*).
SEC("uprobe/incoming_bitfield")
int trace_incoming_bitfield(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);

	// Emit struct dump on first encounter of this peer identity
	emit_peer_dump_if_new(ctx, ptr);

	// No slim event — bitfield is only used for peer discovery.
	return 0;
}

// trace_torrent_start hooks libtorrent::torrent::start().
// Called once when a torrent transitions to started state.
// x86_64 ABI: RDI = this (torrent*).
//
// Always emits a torrent struct dump (struct_dump_t with EVT_TORRENT_STARTED)
// for both info_hash extraction and race creation. These events are
// rare (~1 per torrent) so there is no dedup gating.
//
// The seen_torrents map is shared with trace_we_have to prevent duplicate
// torrent dumps from the we_have path.
SEC("uprobe/torrent_start")
int trace_torrent_start(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);
	u32 key = 0;
	u8 one = 1;

	// Mark this torrent as seen — prevents duplicate dump from trace_we_have
	bpf_map_update_elem(&seen_torrents, &ptr, &one, BPF_ANY);

	// Always emit a full dump (these events are rare — once per torrent)
	struct struct_dump_t *dump = bpf_map_lookup_elem(&dump_scratch, &key);
	if (dump) {
		dump->event_type = EVT_TORRENT_STARTED;
		dump->_pad = 0;
		dump->timestamp = bpf_ktime_get_ns();
		dump->obj_ptr = ptr;
		bpf_probe_read_user(dump->data, DUMP_READ_SIZE, (void *)ptr);
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dump, sizeof(*dump));
	}

	return 0;
}

// trace_torrent_finished hooks libtorrent::torrent::finished().
// Called once when all pieces of a torrent have been downloaded and verified.
// x86_64 ABI: RDI = this (torrent*).
//
// Emits a slim event_t so the coordinator can signal download completion
// for the corresponding race.
SEC("uprobe/torrent_finished")
int trace_torrent_finished(struct pt_regs *ctx) {
	struct event_t event = {};
	event.event_type = EVT_TORRENT_FINISHED;
	event.obj_ptr = PT_REGS_PARM1(ctx);
	event.timestamp = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
