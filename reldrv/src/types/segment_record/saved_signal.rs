use nix::libc::siginfo_t;

use crate::types::execution_point::ExecutionPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalInfo(siginfo_t);

#[derive(Debug)]
pub enum SavedSignal {
    Internal(SignalInfo),
    External(SignalInfo, Box<dyn ExecutionPoint>),
}
