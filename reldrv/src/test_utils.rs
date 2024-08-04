use nix::{
    sys::{
        ptrace,
        signal::{raise, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{fork, ForkResult},
};

use crate::process::OwnedProcess;

pub fn ptraced(f: impl FnOnce() -> i32) -> OwnedProcess {
    match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => {
            let wait_status = waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();
            assert_eq!(wait_status, WaitStatus::Stopped(child, Signal::SIGSTOP));
            ptrace::seize(
                child,
                ptrace::Options::PTRACE_O_TRACESYSGOOD
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_EXITKILL,
            )
            .unwrap();
            OwnedProcess::new(child)
        }
        ForkResult::Child => {
            raise(Signal::SIGSTOP).unwrap();
            let code = f();
            std::process::exit(code)
        }
    }
}

pub fn init_logging() {
    let _ = pretty_env_logger::formatted_builder()
        .parse_default_env()
        .is_test(true)
        .try_init();
}
