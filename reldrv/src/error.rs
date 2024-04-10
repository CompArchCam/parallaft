use std::backtrace::Backtrace;

use procfs::ProcError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnexpectedEventReason {
    /// Application made an excess syscall/trap (possibly due to skidding).
    Excess,

    /// Application made a syscall/trap with unexpected type (sysno) or arguments.
    IncorrectTypeOrArguments,

    /// A checker makes a syscall that has transitive access to memory that diverges from the main.
    IncorrectMemory,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("std::io error: `{0}`")]
    StdIO(#[from] std::io::Error),
    #[error("nix error: `{errno}`")]
    Nix {
        #[from]
        errno: nix::errno::Errno,
        backtrace: Backtrace,
    },
    #[error("Proc error: `{0}`")]
    Proc(#[from] ProcError),
    #[error("Reverie error: `{0}`")]
    Reverie(#[from] reverie_syscalls::Errno),

    #[error("Invalid state")]
    InvalidState,
    #[error("Not handled")]
    NotHandled,
    #[error("Operation cancelled")]
    Cancelled,
    #[error("Unexpected syscall made by the inferior")]
    UnexpectedSyscall(UnexpectedEventReason),
    #[error("Unexpected trap made by the inferior")]
    UnexpectedTrap(UnexpectedEventReason),
    #[error("Not supported: `{0}`")]
    NotSupported(String),

    #[error("Other error")]
    Other,

    #[error("Panic")]
    Panic,

    #[error("Errno returned to user")]
    ReturnedToUser(nix::errno::Errno, String),
}

impl Error {
    pub fn is_potentially_caused_by_skids(&self) -> bool {
        match self {
            Error::UnexpectedSyscall(UnexpectedEventReason::Excess) => true,
            Error::UnexpectedTrap(UnexpectedEventReason::Excess) => true,
            _ => false,
        }
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
            |x| Ok(x),
        )
    }
}
