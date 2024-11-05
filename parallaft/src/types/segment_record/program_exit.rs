use nix::sys::signal::Signal;

use crate::types::exit_reason::ExitCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramExit {
    Exited(ExitCode),
    Killed(Signal),
}
