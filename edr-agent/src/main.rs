use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf}; // Changed Bpf to Ebpf to fix warning
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, debug};
use tokio::signal;
use bytes::BytesMut;
use edr_agent_common::ProcessEvent;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    env_logger::init();

    // 1. Load the eBPF binary
    // Using Ebpf::load instead of Bpf::load to fix the deprecation warning
    // Also pointing to 'release' because our build.rs now forces release builds
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/edr-agent-ebpf"
    ))?;

    // 2. Initialize the Logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        debug!("Standard eBPF logger not active: {}", e);
    }

    // 3. Load the Program
    let program: &mut TracePoint = bpf.program_mut("edr_agent").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    info!("Waiting for Ctrl-C...");

    // 4. Connect to the "Conveyor Belt" (PerfEventArray)
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // 5. Spawn a listener for every CPU core
    // FIX: We map the tuple error manually so 'anyhow' can understand it
    let cpus = online_cpus()
        .map_err(|(msg, error)| anyhow::anyhow!("{}: {}", msg, error))?;

    for cpu_id in cpus {
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();

            loop {
                // Wait for events
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &buffers[i];
                    
                    let ptr = buf.as_ptr() as *const ProcessEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    // Parse the command name (handle null terminators)
                    let len = data.cmd.iter().position(|&c| c == 0).unwrap_or(16);
                    let cmd = std::str::from_utf8(&data.cmd[..len]).unwrap_or("<unknown>");

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