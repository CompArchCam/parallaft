use bitflags::bitflags;
use procfs::ProcError;

bitflags! {
    pub struct EventFlags: u32 {
        /// Inferior made an excess syscall (possibly due to skidding).
        const IS_EXCESS = 0b001;

        /// Inferior made a incorrect syscall.
        const IS_INCORRECT = 0b100;

        /// Ptrace gives an unexpected event.
        const IS_INVALID = 0b100;
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("std::io error: `{0}`")]
    StdIO(#[from] std::io::Error),
    #[error("nix error: `{0}`")]
    Nix(#[from] nix::errno::Errno),
    #[error("Proc error: `{0}`")]
    Proc(#[from] ProcError),
    #[error("Reverie error: `{0}`")]
    Reverie(#[from] reverie_syscalls::Errno),

    #[error("Invalid state")]
    InvalidState,
    #[error("Unexpected syscall made by the inferior")]
    UnexpectedSyscall(EventFlags),
    #[error("Unexpected trap made by the inferior")]
    UnexpectedTrap(EventFlags),
    #[error("Not supported")]
    NotSupported,

    #[error("Other error")]
    Other,

    #[error("Errno returned to user")]
    ReturnedToUser(nix::errno::Errno, String),
}

impl Error {
    pub fn is_potentially_caused_by_skids(&self) -> bool {
        match self {
            Error::UnexpectedSyscall(flags) if flags.contains(EventFlags::IS_EXCESS) => true,
            Error::UnexpectedTrap(flags) if flags.contains(EventFlags::IS_EXCESS) => true,
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
                Error::NotSupported => Ok(()),
                e => Err(e),
            },
            |x| Ok(x),
        )
    }
}
