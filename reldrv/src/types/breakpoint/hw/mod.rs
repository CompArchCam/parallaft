use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        mod aarch64_ptrace;
        pub use aarch64_ptrace::HardwareBreakpointViaPtrace as HardwareBreakpoint;
    } else {
        mod perf;
        pub use perf::HardwareBreakpoint;
    }
}
