use nix::sys::signal::Signal;

use super::checker::CheckFailReason;

pub type ExitCode = i32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    NormalExit(ExitCode),
    Signalled(Signal),
    UnexpectedlyDies,
    StateMismatch(CheckFailReason),
    Cancelled,
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
            ExitReason::Cancelled => 255,
        }
    }

    pub fn expect(self) {
        self.expect_exit_code(0);
    }

    pub fn expect_exit_code(self, code: ExitCode) {
        assert!(matches!(self, ExitReason::NormalExit(c) if c == code));
    }

    pub fn expect_state_mismatch(self) {
        assert!(matches!(self, ExitReason::StateMismatch(_)));
    }
}
