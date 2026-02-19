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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// seen_peers tracks peer_connection* pointers we've already emitted a
// struct dump for. LRU eviction prevents leaks in long-running daemons.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
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
// On first encounter of each peer_connection*, emits a struct dump for
// userspace to extract sockaddr_in, peer_id, and torrent_ptr from.
SEC("uprobe/incoming_have")
int trace_incoming_have(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);

	// Emit struct dump on first encounter of this peer_connection*
	u8 *seen = bpf_map_lookup_elem(&seen_peers, &ptr);
	if (!seen) {
		u8 one = 1;
		bpf_map_update_elem(&seen_peers, &ptr, &one, BPF_ANY);

		u32 key = 0;
		struct struct_dump_t *dump = bpf_map_lookup_elem(&dump_scratch, &key);
		if (!dump)
			goto emit_have;

		dump->event_type = EVT_PEER_DUMP;
		dump->_pad = 0;
		dump->timestamp = bpf_ktime_get_ns();
		dump->obj_ptr = ptr;

		// Read raw struct bytes from user-space peer_connection object.
		// bpf_probe_read_user because uprobes execute in user-space context.
		bpf_probe_read_user(dump->data, DUMP_READ_SIZE, (void *)ptr);

		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dump, sizeof(*dump));
	}

emit_have:;
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

	// Emit struct dump on first encounter of this peer_connection*
	u8 *seen = bpf_map_lookup_elem(&seen_peers, &ptr);
	if (!seen) {
		u8 one = 1;
		bpf_map_update_elem(&seen_peers, &ptr, &one, BPF_ANY);

		u32 key = 0;
		struct struct_dump_t *dump = bpf_map_lookup_elem(&dump_scratch, &key);
		if (!dump)
			return 0;

		dump->event_type = EVT_PEER_DUMP;
		dump->_pad = 0;
		dump->timestamp = bpf_ktime_get_ns();
		dump->obj_ptr = ptr;

		bpf_probe_read_user(dump->data, DUMP_READ_SIZE, (void *)ptr);
		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, dump, sizeof(*dump));
	}

	// No slim event emitted — incoming_piece is only used for peer discovery.
	// The piece data is tracked via we_have (after verification).
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
