fn main() {
    #[cfg(feature = "compel")]
    {
        println!("cargo:rerun-if-changed=parasite/src");
        println!("cargo:rerun-if-changed=parasite/.cargo");
        println!("cargo:rerun-if-changed=parasite/Cargo.toml");
        println!("cargo:rerun-if-changed=parasite/Makefile");
        println!("cargo:rerun-if-changed=parasite-shim.c");

        let status = std::process::Command::new("make")
            .env_clear()
            .env("PATH", std::env!("PATH"))
            .args(&["-C", "parasite"])
            .status()
            .expect("failed to make");

        assert!(status.success());

        cc::Build::new()
            .file("parasite-wrapper.c")
            .compile("parasite");
    }
}
