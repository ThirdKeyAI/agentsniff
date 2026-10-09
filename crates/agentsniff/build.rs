fn main() {
    #[cfg(feature = "ebpf")]
    {
        // Cargo refuses to include a subdirectory in a published crate if that
        // subdirectory contains a `Cargo.toml`. We therefore ship the eBPF
        // crate's manifest as `Cargo.toml.in` and materialise the real
        // `Cargo.toml` at build time inside OUT_DIR before invoking aya_build.
        use std::path::PathBuf;
        let manifest_dir =
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
        let src_root = manifest_dir.join("agentsniff-ebpf");
        let dst_root = out_dir.join("agentsniff-ebpf");

        println!("cargo:rerun-if-changed=agentsniff-ebpf");

        std::fs::create_dir_all(dst_root.join("src")).expect("mkdir ebpf out");
        std::fs::copy(src_root.join("Cargo.toml.in"), dst_root.join("Cargo.toml"))
            .expect("copy Cargo.toml.in -> Cargo.toml");
        if src_root.join("rust-toolchain.toml").exists() {
            std::fs::copy(
                src_root.join("rust-toolchain.toml"),
                dst_root.join("rust-toolchain.toml"),
            )
            .expect("copy rust-toolchain.toml");
        }
        for entry in std::fs::read_dir(src_root.join("src")).expect("read ebpf src") {
            let path = entry.expect("dir entry").path();
            if path.is_file() {
                let dst = dst_root.join("src").join(path.file_name().unwrap());
                std::fs::copy(&path, &dst).expect("copy ebpf src file");
            }
        }

        let dst_root_str = dst_root.to_str().expect("utf8 dst_root");
        let pkg = aya_build::Package {
            name: "agentsniff-ebpf",
            root_dir: dst_root_str,
            ..Default::default()
        };
        aya_build::build_ebpf([pkg], aya_build::Toolchain::default())
            .expect("failed to compile eBPF programs");
    }
}
