use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../edr-agent-ebpf");

    // 1. Determine paths
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let workspace_root = PathBuf::from("..").canonicalize().unwrap();
    
    // 2. Build the eBPF Kernel (Manual Cargo Command)
    // We force --release because eBPF requires optimizations to work correctly
    //
    // SUP-1: `Command::new("cargo")` resolves through PATH, so whatever `cargo`
    // is found first executes on every build of this project. Cargo sets $CARGO
    // to the absolute path of the binary already running, which removes the
    // lookup entirely. The fallback only applies when build.rs is invoked
    // outside cargo, which is not a supported path.
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let status = Command::new(&cargo)
        .current_dir(&workspace_root)
        .args(&[
            "build",
            "--package", "edr-agent-ebpf",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
            "--release" 
        ])
        .status()
        .expect("Failed to run cargo build for eBPF");

    if !status.success() {
        panic!("Failed to build eBPF program");
    }

    // 3. Locate the compiled binary (Standard Rust location)
    let bpf_binary = workspace_root
        .join("target/bpfel-unknown-none/release/edr-agent-ebpf");

    // 4. Copy it to the build output directory so we can access it easily
    let dest_path = out_dir.join("edr-agent-ebpf");
    
    // FORCE CLEANUP: This fixes your "Is a directory" error
    if dest_path.exists() {
        if dest_path.is_dir() {
            fs::remove_dir_all(&dest_path).unwrap();
        } else {
            fs::remove_file(&dest_path).unwrap();
        }
    }

    fs::copy(&bpf_binary, &dest_path).expect("Failed to copy eBPF binary");

    // SUP-5: the compiled object sits in target/ between being built here and
    // being embedded by rustc. If that directory is writable by another user,
    // the bytecode can be swapped in the gap and lands inside an otherwise
    // trusted agent binary. Permissions are the only real fix; warning at build
    // time at least makes the exposure visible rather than silent.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = fs::metadata(workspace_root.join("target")) {
            if md.mode() & 0o022 != 0 {
                println!(
                    "cargo:warning=target/ is group- or world-writable (mode {:o}). \
                     The eBPF object can be replaced between compilation and embedding. \
                     chmod 755 it or build in a private directory.",
                    md.mode() & 0o777
                );
            }
        }
    }
}