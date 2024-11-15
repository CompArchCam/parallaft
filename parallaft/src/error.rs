use std::{backtrace::Backtrace, sync::Arc};

use log::info;
use procfs::ProcError;

use crate::types::{
    exit_reason::ExitReason,
    perf_counter::symbolic_events::expr::PmuError,
    segment_record::saved_event::{SavedEvent, SavedEventType},
};

#[derive(Debug, Clone)]
pub enum UnexpectedEventReason {
    /// Application made an excess syscall/trap (possibly due to skidding).
    Excess,

    /// Application made a syscall/trap with unexpected value (e.g. sysno and syscall arguments).
    IncorrectValue,

    /// Application made a event with unexpected type (e.g. got a signal but expecting a syscall).
    IncorrectType {
        expected: SavedEventType,
        got: SavedEvent,
    },

    /// A checker makes a syscall that has transitive access to memory that diverges from the main.
    IncorrectMemory,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("std::io error: `{0}`")]
    StdIO(Arc<std::io::Error>),
    #[error("nix error: `{0}`")]
    Nix(nix::errno::Errno),
    #[error("Proc error: `{0}`")]
    Proc(Arc<ProcError>),
    #[error("Reverie error: `{0}`")]
    Reverie(#[from] reverie_syscalls::Errno),
    #[error("ParseIntError: `{0}`")]
    ParseInt(#[from] std::num::ParseIntError),

    #[error("Invalid state")]
    InvalidState,
    #[error("Not handled")]
    NotHandled,
    #[error("Operation cancelled")]
    Cancelled,

    #[error("Unexpected event from a checker during replay: `{0:?}`")]
    UnexpectedEvent(UnexpectedEventReason),

    #[error("Not supported: `{0}`")]
    NotSupported(String),

    #[error("Other error")]
    Other,

    #[error("Unexpected checker exit reason: `{0:?}`")]
    UnexpectedCheckerExitReason(ExitReason),

    #[error("Checker timed out")]
    CheckerTimeout,

    #[error("Panic")]
    Panic,

    #[error("Errno returned to user")]
    ReturnedToUser(nix::errno::Errno, String),

    #[error("PMU error: `{0}`")]
    PmuError(#[from] PmuError),

    #[error("Unexpected skid during execution point replay")]
    ExecPointReplayUnexpectedSkid,

    #[cfg(feature = "dpt_uffd")]
    #[error("Userfaultfd error: `{0}`")]
    Userfaultfd(Arc<userfaultfd::Error>),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::StdIO(Arc::new(value))
    }
}

impl From<ProcError> for Error {
    fn from(value: ProcError) -> Self {
        Self::Proc(Arc::new(value))
    }
}

#[cfg(feature = "dpt_uffd")]
impl From<userfaultfd::Error> for Error {
    fn from(value: userfaultfd::Error) -> Self {
        Self::Userfaultfd(Arc::new(value))
    }
}

impl From<nix::errno::Errno> for Error {
    fn from(value: nix::errno::Errno) -> Self {
        info!("Backtrace: {}", Backtrace::capture());
        Self::Nix(value)
    }
}

impl Error {
    pub fn is_potentially_caused_by_skids(&self) -> bool {
        matches!(self, Error::UnexpectedEvent(UnexpectedEventReason::Excess))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait IgnoreNotSupportedErrorExt {
    fn ignore_not_supported_error(self) -> Self;
}

impl IgnoreNotSupportedErrorExt for Result<()> {
    fn ignore_not_supported_error(self) -> Self {
        self.map_or_else(
            |e| match e {
                Error::NotSupported(_) => Ok(()),
                e => Err(e),
            },
            Ok,
        )
    }
}
