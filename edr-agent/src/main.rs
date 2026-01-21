use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use bytes::BytesMut;
use edr_agent_common::ProcessEvent; // <--- The Shared Struct

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // 1. Load the eBPF binary
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/edr-agent-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/edr-agent-ebpf"
    ))?;

    // 2. Initialize the Logger (Optional now, but good to keep if we re-enable it later)
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This is expected now, so we just log a debug message instead of crashing
        debug!("Standard eBPF logger not active (using PerfEventArray instead): {}", e);
    }

    // 3. Load the Program
    let program: &mut TracePoint = bpf.program_mut("edr_agent").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    info!("Waiting for Ctrl-C...");

    // 4. Connect to the "Conveyor Belt" (PerfEventArray)
    // We look for the map named "EVENTS" that we defined in the kernel
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // 5. Spawn a listener for every CPU core
    for cpu_id in online_cpus()? {
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            // Create a buffer to hold the incoming data
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();

            loop {
                // Wait for events
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &buffers[i];
                    
                    // SAFETY: We trust the kernel sent us the right size struct
                    let ptr = buf.as_ptr() as *const ProcessEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    // Decode the Command Name (Bytes -> String)
                    let len = data.cmd.iter().position(|&c| c == 0).unwrap_or(16);
                    let cmd = std::str::from_utf8(&data.cmd[..len]).unwrap_or("<unknown>");

                    // 🚀 THE PAYOFF: Structured Data!
                    info!("🚀 PROCESS START: PID: {} | PPID: {} | CMD: {}", 
                        data.pid, data.ppid, cmd);
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}