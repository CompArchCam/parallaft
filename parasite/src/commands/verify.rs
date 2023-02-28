use crate::{commands::Command, println};
use core::fmt::Write;

pub struct Verify;

#[derive(Clone, Copy, Debug)]
pub struct VerifyRequest {
    pub pid: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct VerifyResponse {
    pub pass: bool
}

impl Command for Verify {
    type Request = VerifyRequest;
    type Response = VerifyResponse;

    fn execute(_cmd: &VerifyRequest) -> VerifyResponse {
        println!("Verifying process {}!", _cmd.pid);
        VerifyResponse { pass: true }
    }
}
