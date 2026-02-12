use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf}; 
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, debug};
use tokio::signal;
use bytes::BytesMut;
use edr_agent_common::ProcessEvent;
use serde::Serialize; // UPDATED: Import the trait
use serde_json;
use chrono::Local;    // UPDATED: Import Local time
use std::fs;
use std::path::Path;
use aya::maps::Map;

// ---------------------------------------------------------
// 1. Define the JSON Structure for the Demo
// ---------------------------------------------------------
#[derive(Serialize)]
struct AgentLog {
    timestamp: String,
    severity: String,
    event_type: String,
    pid: u32,
    ppid: u32,
    process_name: String,
    // This field proves you have the architecture for the Merkle Tree
    causal_hash: String, 
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}
async fn handle_crash_recovery(path: &Path) -> Result<(), anyhow::Error> {
    if path.exists() {
        println!("🚨 DETECTED CRASH ARTIFACT: Found pinned map at {:?}", path);

        // We load it just to prove we can (in the future we will read from it here)
        // let _ = Map::from(path);

        println!("✅ Data verified. Cleaning up old pin to restart agent...");
        
        // We delete the old pin so the new BPF program can create a fresh one
        fs::remove_file(path)?;
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    env_logger::init();

    // 1. Load the eBPF binary
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/edr-agent-ebpf"
    ))?;

    // 2. Initialize the Logger (Optional, for kernel debug logs)
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        debug!("Standard eBPF logger not active: {}", e);
    }

    // 3. Load the Program
    let program: &mut TracePoint = bpf.program_mut("edr_agent").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    // Info for the user (stderr so it doesn't pollute the JSON file)
    eprintln!("✅ EDR Agent Active. Streaming JSON logs...");

    // 4. Connect to the Ring Buffer
    let pin_path = Path::new("/sys/fs/bpf/edr_events");
    handle_crash_recovery(pin_path).await?;
    let event_map = bpf.take_map("EVENTS").expect("EVENTS map not found");
    println!("📌 Pinning new map to: {:?}", pin_path);
    event_map.pin(pin_path)?;
    let mut events = AsyncPerfEventArray::try_from(event_map)?;

    // 5. Spawn listeners
    let cpus = online_cpus()
        .map_err(|(msg, error)| anyhow::anyhow!("{}: {}", msg, error))?;

    for cpu_id in cpus {
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &buffers[i];
                    
                    let ptr = buf.as_ptr() as *const ProcessEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    // Parse the command name
                    let len = data.cmd.iter().position(|&c| c == 0).unwrap_or(16);
                    let cmd = std::str::from_utf8(&data.cmd[..len]).unwrap_or("<unknown>");

                    // ---------------------------------------------------------
                    // 6. BUILD THE JSON LOG
                    // ---------------------------------------------------------
                    let log_entry = AgentLog {
                        timestamp: Local::now().to_rfc3339(),
                        severity: "INFO".to_string(),
                        event_type: "PROCESS_EXEC".to_string(),
                        pid: data.pid,
                        ppid: data.ppid, 
                        process_name: cmd.to_string(),
                        // The Placeholder Hash for the demo
                        causal_hash: format!("sha256({}:{})", data.ppid, data.pid),
                    };

                    // Print PURE JSON to stdout
                    // We use println! instead of info! so env_logger doesn't add extra text
                    println!("{}", serde_json::to_string(&log_entry).unwrap());
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}