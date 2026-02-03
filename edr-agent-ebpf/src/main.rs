#![no_std]
#![no_main]

// THE MAGIC MODULE IS HERE
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
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm, bpf_get_current_task_btf},
};
use edr_agent_common::ProcessEvent;

#[map]
static EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

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

    // 1. Get the Task Struct
    let task = unsafe { bpf_get_current_task_btf() as *const task_struct };
    
    // 2. Read the Real Parent PID (No Mocking!)
    let ppid = unsafe {
        if !task.is_null() {
            let parent = (*task).real_parent;
            if !parent.is_null() {
                (*parent).tgid as u32
            } else {
                0
            }
        } else {
            0
        }
    };

    let event = ProcessEvent {
        pid: pid,
        ppid: ppid, // 100% Real Data
        cmd: comm,
    };

    EVENTS.output(&ctx, &event, 0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";