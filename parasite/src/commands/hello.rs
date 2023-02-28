use crate::{commands::Command, println};
use core::fmt::Write;

pub struct Hello;

#[derive(Clone, Copy, Debug)]
pub struct HelloRequest;

#[derive(Clone, Copy, Debug)]
pub struct HelloResponse;

impl Command for Hello {
    type Request = HelloRequest;
    type Response = HelloResponse;

    fn execute(_cmd: &HelloRequest) -> HelloResponse {
        println!("Hello world!");
        HelloResponse
    }
}
