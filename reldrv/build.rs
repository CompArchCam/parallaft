use std::process::Command;

fn compile_shellcode(out_dir: &str, name: &'static str) {
    let source_filename = format!("remote/{}.c", name);
    let intermediate_filename = format!("{}/{}.elf", out_dir, name);
    let output_filename = format!("{}/{}.bin", out_dir, name);

    let is_ok = Command::new("gcc")
        .arg("-o")
        .arg(&intermediate_filename)
        .arg("-O3")
        .arg("-D_FORTIFY_SOURCE=0")
        .arg("-Wstrict-prototypes")
        .arg("-ffreestanding")
        .arg("-fno-stack-protector")
        .arg("-nostdlib")
        .arg("-fomit-frame-pointer")
        .arg("-fpie")
        .arg("-z")
        .arg("noexecstack")
        .arg("-T")
        .arg("remote/pack.lds.S")
        .arg(&source_filename)
        .arg("remote/arch/aarch64/entry.s")
        .arg("remote/arch/aarch64/syscall.s")
        .status()
        .expect("Failed to run gcc");

    assert!(is_ok.success(), "gcc returns with an error");

    let is_ok = Command::new("objcopy")
        .arg("-O")
        .arg("binary")
        .arg(&intermediate_filename)
        .arg(&output_filename)
        .status()
        .expect("Failed to run objcopy");

    assert!(is_ok.success(), "objcopy returns with an error");
}

fn main() {
    println!("cargo:rerun-if-changed=remote");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    compile_shellcode(&out_dir, "hasher");
}
