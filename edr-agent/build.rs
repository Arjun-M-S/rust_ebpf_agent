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

    // A nested `cargo build` inherits the outer cargo's target dir by default,
    // which means it fights the outer process for the same target/.cargo-lock
    // and deadlocks: the parent holds the lock until this build script exits,
    // and this build script can't exit until the child gets the lock it's
    // waiting on. A separate --target-dir sidesteps the shared lock entirely.
    let bpf_target_dir = workspace_root.join("target/bpf-build");

    let status = Command::new(&cargo)
        .current_dir(&workspace_root)
        .args(&[
            "build",
            "--package", "edr-agent-ebpf",
            "--target", "bpfel-unknown-none",
            "--target-dir", bpf_target_dir.to_str().unwrap(),
            "-Z", "build-std=core",
            // LLVM lowers a large enough struct initialisation to a memset
            // call, and the BPF backend rejects calls to builtins it cannot
            // resolve: "A call to built-in function 'memset' is not supported".
            // compiler_builtins' `mem` feature supplies real definitions, which
            // bpf-linker then exports, so the call resolves instead of failing.
            "-Z", "build-std-features=compiler-builtins-mem",
            "--release"
        ])
        .status()
        .expect("Failed to run cargo build for eBPF");

    if !status.success() {
        panic!("Failed to build eBPF program");
    }

    // 3. Locate the compiled binary
    let bpf_binary = bpf_target_dir.join("bpfel-unknown-none/release/edr-agent-ebpf");

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
        if let Ok(md) = fs::metadata(&bpf_target_dir) {
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