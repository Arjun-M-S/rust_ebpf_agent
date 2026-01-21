#![no_std]
#![no_main]

use aya_ebpf::{macros::{map, tracepoint}, programs::TracePointContext};
use aya_ebpf::maps::PerfEventArray;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm};
use edr_agent_common::ProcessEvent; 

// 1. The Ring Buffer Map ("The Conveyor Belt")
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
    // 2. Get PID
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // 3. Get Command Name
    let comm = bpf_get_current_comm().unwrap_or([0; 16]);

    // 4. Create the Event Struct
    // Note: We set ppid to 0 for now to avoid the 'vmlinux' dependency errors.
    // We will fix this in the next phase.
    let event = ProcessEvent {
        pid: pid,
        ppid: 0, 
        cmd: comm,
    };

    // 5. Send to User Space
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