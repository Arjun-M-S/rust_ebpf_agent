use std::env;
use std::path::PathBuf;
use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// SUP-1: PATH lookup decides which `bpf-linker` ends up producing the kernel
/// bytecode for a security agent, and rustc will invoke it. `which` is only the
/// cache key here, but it resolves the same way rustc does, so pinning it pins
/// both. $BPF_LINKER takes an absolute path and skips the search entirely; a
/// hardened or CI build should set it.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    println!("cargo:rerun-if-env-changed=BPF_LINKER");

    let bpf_linker: PathBuf = match env::var_os("BPF_LINKER") {
        Some(explicit) => {
            let path = PathBuf::from(explicit);
            if !path.is_absolute() {
                panic!("BPF_LINKER must be an absolute path, got {:?}", path);
            }
            if !path.exists() {
                panic!("BPF_LINKER points at {:?}, which does not exist", path);
            }
            path
        }
        None => which("bpf-linker").unwrap_or_else(|e| {
            panic!(
                "bpf-linker not found on PATH ({e}). Install it with \
                 `cargo install bpf-linker`, or set BPF_LINKER to an absolute path."
            )
        }),
    };

    println!(
        "cargo:rerun-if-changed={}",
        bpf_linker
            .to_str()
            .expect("bpf-linker path is not valid UTF-8")
    );
}
