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
    maps::PerfEventArray,
    // as_ptr() comes from this trait, not from TracePointContext itself.
    EbpfContext,
};
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid,
    bpf_get_current_comm,
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
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = uid_gid as u32;

    // NOW-12: stamp the event in the kernel, at the moment it happens. A
    // timestamp taken later in userspace reflects queue latency, which an
    // attacker can inflate at will by flooding the pipeline.
    let ktime_ns = unsafe { bpf_ktime_get_ns() };

    // SEN-1: cgroup id survives double-fork reparenting. When an attacker
    // orphans a process to break ppid/pcomm, this still ties it to the
    // service it came from.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };

    let mut pcomm = [0u8; 16];

    let ppid = unsafe {
        if !task.is_null() {
            let parent_ptr: *mut task_struct =
                bpf_probe_read_kernel(&(*task).real_parent).unwrap_or(core::ptr::null_mut());
            if !parent_ptr.is_null() {
                // comm is [c_char; 16] (i8), so cast to *const u8 for the buf read.
                let _ = bpf_probe_read_kernel_buf(
                    &(*parent_ptr).comm as *const _ as *const u8,
                    &mut pcomm
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
    let mut filename = [0u8; 128];
    unsafe {
        if let Ok(data_loc) = ctx.read_at::<u32>(FILENAME_DATA_LOC_OFFSET) {
            let offset = (data_loc & 0xFFFF) as usize;
            if offset > 0 {
                let src = (ctx.as_ptr() as *const u8).add(offset);
                let _ = bpf_probe_read_kernel_str_bytes(src, &mut filename);
            }
        }
    }

    let event = ProcessEvent {
        ktime_ns,
        cgroup_id,
        pid,
        ppid: ppid as u32,
        uid,
        _pad: 0,
        cmd: comm,
        pcomm,
        filename,
    };

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
