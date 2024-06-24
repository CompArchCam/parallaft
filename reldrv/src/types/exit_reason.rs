use nix::sys::signal::Signal;

use crate::error::Error;

use super::checker::CheckFailReason;

pub type ExitCode = i32;

#[derive(Debug)]
pub enum ExitReason {
    NormalExit(ExitCode),
    Signalled(Signal),
    UnexpectedlyDies,
    StateMismatch(CheckFailReason),
    Crashed(Error),
}

// pub fn unwrap_result_with(f: impl FnOnce() -> Result<ExitReason>) -> ExitReason {
//     f().unwrap_or_else(|err| ExitReason::Crashed(err))
// }

impl ExitReason {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            ExitReason::NormalExit(c) => *c,
            ExitReason::Signalled(sig) => 128 + (*sig as i32),
            ExitReason::StateMismatch(_) => 253,
            ExitReason::UnexpectedlyDies => 254,
            ExitReason::Crashed(_) => 255,
        }
    }

    pub fn expect(self) {
        self.expect_exit_code(0);
    }

    pub fn expect_crash(self) {
        assert!(matches!(self, ExitReason::Crashed(_)));
    }

    pub fn expect_exit_code(self, code: ExitCode) {
        assert!(matches!(self, ExitReason::NormalExit(c) if c == code));
    }

    pub fn expect_state_mismatch(self) {
        assert!(matches!(self, ExitReason::StateMismatch(_)));
    }
}
