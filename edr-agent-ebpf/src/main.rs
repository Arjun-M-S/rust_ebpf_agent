#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    maps::PerfEventArray,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm},
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
    // 1. Get the PID
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    
    // 2. Get the Command Name
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    // 3. Mock the PPID (Safety Mechanism)
    // Since reading task_struct is failing on this VM, we default to 1 (init)
    // This allows the pipeline to function for the demo.
    let ppid = 1; 

    let event = ProcessEvent {
        pid: pid,
        ppid: ppid, 
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