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
    let status = Command::new("cargo")
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
}