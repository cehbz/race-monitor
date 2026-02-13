//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define EVT_WE_HAVE        1
#define EVT_INCOMING_HAVE   2
#define EVT_CALIBRATION     3

#define CALIBRATION_READ_SIZE 512

// event_t is the perf event structure emitted to userspace.
// Zero struct offset reads — we only capture function arguments and the this pointer.
struct event_t {
	u32 event_type;
	u32 piece_index;
	u64 timestamp;
	u64 obj_ptr;  // this pointer: torrent* for we_have, peer_connection* for incoming_have
};

// calibration_event_t is emitted once per new peer_connection* to enable
// auto-discovery of the sockaddr_in offset within the peer_connection struct.
// Userspace scans the 512-byte dump for known peer IP:port patterns.
struct calibration_event_t {
	u32 event_type;  // EVT_CALIBRATION
	u32 _pad;        // alignment padding
	u64 timestamp;
	u64 obj_ptr;     // peer_connection*
	u8  data[CALIBRATION_READ_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// seen_peers tracks peer_connection* pointers we've already emitted a
// calibration event for. LRU eviction prevents leaks in long-running daemons.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} seen_peers SEC(".maps");

// Per-CPU scratch space for calibration_event_t to avoid exceeding the
// 512-byte BPF stack limit. Each CPU gets its own copy, so no locking needed.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct calibration_event_t);
} cal_scratch SEC(".maps");

// trace_we_have hooks libtorrent::torrent::we_have(piece_index_t).
// Called once per completed+verified piece. Very low frequency (~1K/race).
// x86_64 ABI: RDI = this (torrent*), RSI = piece_index (strong_typedef<int> passed as int).
SEC("uprobe/we_have")
int trace_we_have(struct pt_regs *ctx) {
	struct event_t event = {};
	event.event_type = EVT_WE_HAVE;
	event.obj_ptr = PT_REGS_PARM1(ctx);
	event.piece_index = (u32)PT_REGS_PARM2(ctx);
	event.timestamp = bpf_ktime_get_ns();

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}

// trace_incoming_have hooks libtorrent::peer_connection::incoming_have(piece_index_t).
// Called when a peer announces it has a piece. Moderate frequency (~3K/sec peak).
// x86_64 ABI: RDI = this (peer_connection*), RSI = piece_index.
//
// On first encounter of each peer_connection*, emits a calibration event containing
// 512 bytes of raw struct data for userspace auto-calibration of the sockaddr_in offset.
SEC("uprobe/incoming_have")
int trace_incoming_have(struct pt_regs *ctx) {
	u64 ptr = PT_REGS_PARM1(ctx);

	// Emit calibration event on first encounter of this peer_connection*
	u8 *seen = bpf_map_lookup_elem(&seen_peers, &ptr);
	if (!seen) {
		u8 one = 1;
		bpf_map_update_elem(&seen_peers, &ptr, &one, BPF_ANY);

		// Use per-CPU scratch map instead of stack allocation to stay
		// within the 512-byte BPF stack limit.
		u32 key = 0;
		struct calibration_event_t *cal = bpf_map_lookup_elem(&cal_scratch, &key);
		if (!cal)
			goto emit_have;

		__builtin_memset(cal, 0, sizeof(*cal));
		cal->event_type = EVT_CALIBRATION;
		cal->timestamp = bpf_ktime_get_ns();
		cal->obj_ptr = ptr;

		// Read raw struct bytes from user-space peer_connection object.
		// bpf_probe_read_user because uprobes execute in user-space context.
		bpf_probe_read_user(cal->data, CALIBRATION_READ_SIZE, (void *)ptr);

		bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, cal, sizeof(*cal));
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
