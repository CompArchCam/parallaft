use std::fmt::Debug;

use super::Process;

pub trait ProcessState: Clone + Debug {
    fn is_owned(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running;
impl ProcessState for Running {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stopped;
impl ProcessState for Stopped {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unowned;
impl ProcessState for Unowned {
    fn is_owned(&self) -> bool {
        false
    }
}

// #[derive(Debug)]
pub struct WithProcess<S: ProcessState, T>(pub Process<S>, pub T);

impl<S: ProcessState, T> From<WithProcess<S, T>> for (Process<S>, T) {
    fn from(value: WithProcess<S, T>) -> Self {
        (value.0, value.1)
    }
}

impl<S: ProcessState, T> From<(Process<S>, T)> for WithProcess<S, T> {
    fn from(value: (Process<S>, T)) -> Self {
        WithProcess(value.0, value.1)
    }
}
