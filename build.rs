use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=parasite");
    println!("cargo:rerun-if-changed=parasite-shim.c");

    let status = Command::new("make")
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
