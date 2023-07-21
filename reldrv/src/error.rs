use procfs::ProcError;

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
    UnexpectedSyscall,
    #[error("Unexpected trap made by the inferior")]
    UnexpectedTrap,
    #[error("Not supported")]
    NotSupported,

    #[error("Other error")]
    Other,

    #[error("Errno returned to user")]
    ReturnedToUser(nix::errno::Errno, String),
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
