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
use serde::Serialize;
use serde_json;
use chrono::Local;
use std::fs;
use std::path::Path;
use aya::maps::Map;
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt; // Needed for file writing
use sha2::{Sha256, Digest};   // NEW: Needed for the Tamper-Evident Chain

// ---------------------------------------------------------
// 1. Define the JSON Structure
// ---------------------------------------------------------
#[derive(Serialize)]
struct AgentLog {
    timestamp: String,
    severity: String,
    event_type: String,
    uid: u32,
    pid: u32,
    ppid: u32,
    process_name: String,
    parent_process_name: String,
    // THE CRYPTO FIELDS
    prev_hash: String, 
    hash: String,      
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

// ---------------------------------------------------------
// 2. Recovery Logic
// ---------------------------------------------------------
async fn handle_crash_recovery(path: &Path) -> Result<(), anyhow::Error> {
    if path.exists() {
        println!("🚨 DETECTED CRASH ARTIFACT: Found pinned map at {:?}", path);
        // In the future: Load map here to read missed events
        println!("✅ Data verified. Cleaning up old pin to restart agent...");
        fs::remove_file(path)?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();
    env_logger::init();

    // ---------------------------------------------------------
    // 3. SETUP WAL (Failsafe)
    // ---------------------------------------------------------
    let mut wal_file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/edr.wal")
        .await?;

    // Create the channel: tx (Sensor) -> rx (Logger)
    let (tx, mut rx) = mpsc::channel::<AgentLog>(1000);

    // Spawn the Consumer (Logger) Task
    tokio::spawn(async move {
        // 1. Initialize the "Genesis Hash" (Start of the chain)
        let mut last_hash = String::from("0000000000000000000000000000000000000000000000000000000000000000");

        // NOTE: We made `log` mutable here so we can update the hash fields
        while let Some(mut log) = rx.recv().await {
            
            // 2. Attach the previous hash to the current log
            log.prev_hash = last_hash.clone();

            // 3. Create the cryptographic payload (Data + Prev Hash)
            let data_to_hash = format!(
                "{}{}{}{}{}", 
                log.timestamp, log.uid, log.pid, log.process_name, log.prev_hash
            );

            // 4. Calculate the SHA256 Hash
            let mut hasher = Sha256::new();
            hasher.update(data_to_hash.as_bytes());
            let current_hash = hex::encode(hasher.finalize());

            // 5. Lock in the current hash and update state for the next loop
            log.hash = current_hash.clone();
            last_hash = current_hash; 

            // 6. Serialize the final cryptographically sealed log
            let json = serde_json::to_string(&log).unwrap();

            // A. Write to Disk (The Failsafe)
            if let Err(e) = wal_file.write_all(format!("{}\n", json).as_bytes()).await {
                eprintln!("CRITICAL: WAL Write Failed: {}", e);
            }
            // Flush ensures it's physically on the disk, not just in RAM
            if let Err(e) = wal_file.flush().await {
                eprintln!("CRITICAL: WAL Flush Failed: {}", e);
            }

            // B. Send to Network (Stdout for now)
            println!("{}", json);
        }
    });

    // ---------------------------------------------------------
    // 4. LOAD BPF (Core Engine)
    // ---------------------------------------------------------
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/edr-agent-ebpf"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        debug!("Standard eBPF logger not active: {}", e);
    }

    let program: &mut TracePoint = bpf.program_mut("edr_agent").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    eprintln!("✅ EDR Agent Active. Streaming JSON logs...");

    // ---------------------------------------------------------
    // 5. PINNING (Persistence)
    // ---------------------------------------------------------
    let pin_path = Path::new("/sys/fs/bpf/edr_events");
    
    // Check for crash data before we overwrite it
    handle_crash_recovery(pin_path).await?;
    
    // MUTABILITY FIX: Added 'mut' here
    let mut event_map = bpf.take_map("EVENTS").expect("EVENTS map not found");
    
    println!("📌 Pinning new map to: {:?}", pin_path);
    event_map.pin(pin_path)?;
    
    let mut events = AsyncPerfEventArray::try_from(event_map)?;

    // ---------------------------------------------------------
    // 6. SPAWN SENSORS (Producer)
    // ---------------------------------------------------------
    let cpus = online_cpus()
        .map_err(|(msg, error)| anyhow::anyhow!("{}: {}", msg, error))?;

    for cpu_id in cpus {
        let mut buf = events.open(cpu_id, None)?;
        // Clone the transmitter for this thread
        let tx = tx.clone(); 

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(1024)).collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &buffers[i];
                    let ptr = buf.as_ptr() as *const ProcessEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let len = data.cmd.iter().position(|&c| c == 0).unwrap_or(16);
                    let cmd = std::str::from_utf8(&data.cmd[..len]).unwrap_or("<unknown>");
                    
                    let p_len = data.pcomm.iter().position(|&c| c == 0).unwrap_or(16);
                    let pcomm_str = std::str::from_utf8(&data.pcomm[..p_len]).unwrap_or("<unknown>");
                    
                    let log_entry = AgentLog {
                        timestamp: Local::now().to_rfc3339(),
                        severity: "INFO".to_string(),
                        event_type: "PROCESS_EXEC".to_string(),
                        uid: data.uid,
                        pid: data.pid,
                        ppid: data.ppid, 
                        process_name: cmd.to_string(),
                        parent_process_name: pcomm_str.to_string(),
                        
                        // We leave these blank. The Consumer Thread calculates 
                        // them safely to prevent Race Conditions!
                        prev_hash: String::new(),
                        hash: String::new(),
                    };

                    // Send to the Logger Channel instead of printing directly
                    if let Err(e) = tx.send(log_entry).await {
                        eprintln!("Error sending to logger: {}", e);
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    info!("Exiting...");

    // NOTE: We do NOT unpin here. We want the kernel map to survive exit!
    Ok(())
}