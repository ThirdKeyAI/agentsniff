fn main() {
    #[cfg(feature = "ebpf")]
    {
        let pkg = aya_build::Package {
            name: "agentsniff-ebpf",
            root_dir: "../agentsniff-ebpf",
            ..Default::default()
        };
        aya_build::build_ebpf([pkg], aya_build::Toolchain::default())
            .expect("failed to compile eBPF programs");
    }
}
