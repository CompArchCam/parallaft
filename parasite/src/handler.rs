use crate::commands::{handle_request, Request, Response};
use core::fmt::Write;

use crate::{eprintln, println};

pub trait Parasite<T: Copy, R: Copy> {
    fn trap_cmd(&mut self, cmd: u32, args: T) -> R;
    fn daemon_cmd(&mut self, cmd: u32, args: T) -> R;
    fn cleanup(&mut self);
}

pub struct Handler;

impl Parasite<Request, Response> for Handler {
    fn trap_cmd(&mut self, _cmd: u32, args: Request) -> Response {
        // eprintln!("Trap Command in, req = {:?}", args);
        handle_request(&args)
    }

    fn daemon_cmd(&mut self, _cmd: u32, args: Request) -> Response {
        // eprintln!("Deamon command in, req = {:?}", args);
        handle_request(&args)
    }

    fn cleanup(&mut self) {}
}

pub static mut HANDLER: Handler = Handler;
