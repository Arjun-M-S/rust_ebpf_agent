#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::task_struct;
use aya_ebpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    maps::{PerCpuArray, PerfEventArray},
    // as_ptr() comes from this trait, not from TracePointContext itself.
    EbpfContext,
};
use aya_ebpf::helpers::{
    gen,
    bpf_get_current_pid_tgid,
    bpf_get_current_task_btf,
    bpf_probe_read_kernel,
    bpf_probe_read_kernel_buf,
    bpf_probe_read_kernel_str_bytes,
    bpf_get_current_uid_gid,
    bpf_get_current_cgroup_id,
    bpf_ktime_get_ns,
};
use edr_agent_common::ProcessEvent;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

/// Scratch space for the event being assembled.
///
/// ProcessEvent is 192 bytes, and assembling it on the stack -- alongside the
/// 128-byte filename buffer it needs -- makes LLVM emit a `memset` call for the
/// zero-initialisation. There is no libc in BPF, so the backend rejects that
/// call outright and the link fails. Map memory is allocated and zeroed by the
/// kernel, so building the event here emits plain stores and nothing else.
///
/// Per-CPU, so no other CPU shares this slot, and a tracepoint cannot preempt
/// itself on the CPU it is running on.
#[map]
static SCRATCH: PerCpuArray<ProcessEvent> = PerCpuArray::with_max_entries(1, 0);

/// Offset of the `__data_loc char[] filename` field in the
/// sched:sched_process_exec tracepoint record. From its format file:
///
///   offset:0  size:2  common_type
///   offset:2  size:1  common_flags
///   offset:3  size:1  common_preempt_count
///   offset:4  size:4  common_pid
///   offset:8  size:4  __data_loc char[] filename   <-- this
///   offset:12 size:4  pid
///   offset:16 size:4  old_pid
///
/// A __data_loc field is a u32: the low 16 bits are the byte offset of the
/// payload from the start of the record, the high 16 bits are its length.
const FILENAME_DATA_LOC_OFFSET: usize = 8;

#[tracepoint]
pub fn edr_agent(ctx: TracePointContext) -> u32 {
    match try_edr_agent(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_edr_agent(ctx: TracePointContext) -> Result<u32, u32> {
    let event = unsafe { &mut *SCRATCH.get_ptr_mut(0).ok_or(0u32)? };

    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // The safe `bpf_get_current_comm()` wrapper returns the buffer by value,
    // which LLVM lowers to a stack alloca plus two `memset`s and a `memcpy`.
    // The BPF backend refuses to lower those to a call ("A call to built-in
    // function 'memset' is not supported"), so the link fails. The raw helper
    // writes straight into map memory: no temporary, no intrinsic. It NUL-fills
    // the buffer itself on success; the explicit terminator covers failure so a
    // stale comm from the previous exec on this CPU cannot leak through.
    event.cmd[0] = 0;
    unsafe {
        gen::bpf_get_current_comm(
            event.cmd.as_mut_ptr() as *mut core::ffi::c_void,
            event.cmd.len() as u32,
        );
    }

    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    event.uid = uid_gid as u32;

    // NOW-12: stamp the event in the kernel, at the moment it happens. A
    // timestamp taken later in userspace reflects queue latency, which an
    // attacker can inflate at will by flooding the pipeline.
    event.ktime_ns = unsafe { bpf_ktime_get_ns() };

    // SEN-1: cgroup id survives double-fork reparenting. When an attacker
    // orphans a process to break ppid/pcomm, this still ties it to the
    // service it came from.
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Userspace rejects any event whose padding is non-zero, so state it here
    // rather than inheriting whatever the previous exec on this CPU left.
    event._pad = 0;

    // This slot still holds the previous exec's data. Both string reads below
    // can fail, and both stop at the NUL they write, so terminate each one up
    // front: without this a failed read ships the previous process's name as if
    // it belonged to this one.
    event.pcomm[0] = 0;
    event.filename[0] = 0;

    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };

    let ppid = unsafe {
        if !task.is_null() {
            let parent_ptr: *mut task_struct =
                bpf_probe_read_kernel(&(*task).real_parent).unwrap_or(core::ptr::null_mut());
            if !parent_ptr.is_null() {
                // comm is [c_char; 16] (i8), so cast to *const u8 for the buf read.
                let _ = bpf_probe_read_kernel_buf(
                    &(*parent_ptr).comm as *const _ as *const u8,
                    &mut event.pcomm
                );

                bpf_probe_read_kernel(&(*parent_ptr).tgid).unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        }
    };

    // SEN-4: the full path, not the 15-byte comm. `systemd-journaldX` and
    // `systemd-journald` are indistinguishable in comm; here they are not.
    //
    // The string already sits in the tracepoint buffer, so this costs one
    // bounded copy and no extra kernel work. _str_bytes is used rather than a
    // length-driven _buf read because it stops at the NUL and takes its bound
    // from the destination, which keeps the verifier happy without needing to
    // trust the length encoded in the data_loc.
    unsafe {
        if let Ok(data_loc) = ctx.read_at::<u32>(FILENAME_DATA_LOC_OFFSET) {
            let offset = (data_loc & 0xFFFF) as usize;
            if offset > 0 {
                let src = (ctx.as_ptr() as *const u8).add(offset);
                let _ = bpf_probe_read_kernel_str_bytes(src, &mut event.filename);
            }
        }
    }

    event.ppid = ppid as u32;

    EVENTS.output(&ctx, event, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
