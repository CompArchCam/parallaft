// Run with `cargo test benches::syscall -- --include-ignored --nocapture --test-threads=1`

use std::{fs::File, io::Read};

use nix::unistd::getpid;

use crate::common::{checkpoint_fini, checkpoint_take};

use super::run_suite;

fn kernel_getpid(n_iters: usize) {
    checkpoint_take();
    for _ in 0..n_iters {
        getpid();
    }
    checkpoint_fini();
}

fn kernel_read(block_size: usize, n_iters: usize) {
    let mut file = File::open("/dev/zero").expect("open");
    let mut buf = vec![0u8; block_size];

    checkpoint_take();
    for _ in 0..n_iters {
        let bytes_read = file.read(&mut buf).unwrap();
        assert_eq!(bytes_read, block_size);
    }
    checkpoint_fini();
}

#[ignore = "benchmark use only"]
#[test]
fn run_syscall_getpid_bench_set() {
    run_suite("getpid", 20, || kernel_getpid(100000));
}

#[ignore = "benchmark use only"]
#[test]
fn run_syscall_read_1k_bench_set() {
    run_suite("read 1k", 20, || kernel_read(1024, 100000));
}

#[ignore = "benchmark use only"]
#[test]
fn run_syscall_read_32k_bench_set() {
    run_suite("read 32k", 20, || kernel_read(32768, 10000));
}

#[ignore = "benchmark use only"]
#[test]
fn run_syscall_read_1m_bench_set() {
    run_suite("read 1M", 20, || kernel_read(1024 * 1024, 1000));
}
