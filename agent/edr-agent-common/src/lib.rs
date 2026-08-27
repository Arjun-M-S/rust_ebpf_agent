// The kernel <-> userspace ABI, and nothing else. Always no_std: the eBPF probe
// compiles this crate, so anything that pulls in std or a dependency does not
// belong here. The sealed record format lives in the `edr-record` crate
// (../../protocol), shared with the collector.
#![no_std]

/// The kernel <-> userspace ABI. Both sides must agree byte-for-byte.
///
/// u64 fields are declared first so the struct has no implicit padding: the
/// userspace side reads this back with `read_unaligned` from a perf record, and
/// compiler-inserted padding would be uninitialised bytes crossing the boundary.
/// Current size: 8+8+4+4+4+4+16+16+128 = 192 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    /// NOW-12: kernel event time (CLOCK_MONOTONIC via bpf_ktime_get_ns).
    /// Taken at the moment of exec, not when userspace gets round to reading it.
    pub ktime_ns: u64,
    /// SEN-1: survives double-fork reparenting, unlike ppid/pcomm.
    pub cgroup_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// Explicit padding so the layout is stated rather than inferred.
    pub _pad: u32,
    /// Truncated to 15 chars + NUL by the kernel. See `filename` for the real one.
    pub cmd: [u8; 16],
    pub pcomm: [u8; 16],
    /// SEN-4: full path from the tracepoint's __data_loc filename field.
    /// Defeats the rename-to-15-chars masquerade that `cmd` alone allows.
    pub filename: [u8; 128],
}
