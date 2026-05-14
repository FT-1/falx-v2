// =============================================================================
// Project: FALX V2
// Lead Architect & Owner: FT-1
// Description: build.rs for ebpf-user — compiles the BPF kernel crate and
//              embeds the resulting object into the loader binary.
// =============================================================================

use std::path::PathBuf;
use std::process::Command;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=../ebpf-kern/src");
    println!("cargo:rerun-if-changed=../ebpf-kern/Cargo.toml");

    let out_dir      = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let kern_dir     = manifest_dir.join("../ebpf-kern");
    let target_dir   = out_dir.join("bpf-target");

    // Build the BPF kernel program in a clean rustflags environment.
    // RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS from the parent shell (or from the
    // outer `cargo build`) override per-target settings in .cargo/config.toml,
    // which is how `-C target-cpu=native` leaks into the BPF compilation and
    // makes bpf-linker reject "--cpu alderlake". We remove them explicitly
    // and set a complete, self-contained set of flags for the BPF target.
    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
            "--release",
            "--target-dir",
        ])
        .arg(&target_dir)
        .current_dir(&kern_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env(
            "CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS",
            "-C panic=abort \
             -C target-cpu=generic \
             -C link-arg=--disable-memory-builtins",
        )
        .status()
        .expect("Failed to spawn cargo for BPF kernel build");

    if !status.success() {
        panic!(
            "BPF kernel crate build FAILED. \
             Run: rustup +nightly target add bpfel-unknown-none \
             and: cargo install bpf-linker"
        );
    }

    let bpf_bin = target_dir.join("bpfel-unknown-none/release/falx-kern");
    let dest    = out_dir.join("falx-kern.bpf.o");

    std::fs::copy(&bpf_bin, &dest).unwrap_or_else(|e| {
        panic!("Cannot copy BPF binary: {}", e)
    });

    println!("cargo:rustc-env=FALX_BPF_OBJ={}", dest.display());
}
