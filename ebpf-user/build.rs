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

    // Build the BPF kernel program. We strip RUSTFLAGS / CARGO_*RUSTFLAGS
    // env vars inherited from the parent shell (the outer `cargo build` for
    // ebpf-user sets these for the host target, which would otherwise leak
    // host-CPU flags into the BPF cross-compile — e.g. `target-cpu=native`
    // resolving to `alderlake` which bpf-linker rejects).
    //
    // We deliberately DO NOT set CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS
    // here: cargo APPENDS that env var to [target.bpfel-unknown-none].rustflags
    // in .cargo/config.toml rather than replacing it, so passing the same flag
    // in both places causes "--disable-memory-builtins" to appear twice in the
    // linker invocation and bpf-linker errors out with
    // "the argument '--disable-memory-builtins' cannot be used multiple times".
    //
    // All BPF rustflags now live in ONE place: .cargo/config.toml.
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
        .env_remove("CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS")
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
