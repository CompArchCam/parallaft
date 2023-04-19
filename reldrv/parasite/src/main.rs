#![no_std]
#![no_main]

mod commands;
mod handler;
mod log;

use core::ffi::{c_int, c_void};
use core::fmt::Write;
use handler::Parasite;
use syscalls::syscall;

#[no_mangle]
pub extern "C" fn parasite_trap_cmd(cmd: c_int, args: *mut c_void) -> c_int {
    unsafe {
        let ret = handler::HANDLER.trap_cmd(cmd as u32, *(args as *mut _));
        *(args as *mut _) = ret;
    }
    0
}

#[no_mangle]
pub extern "C" fn parasite_cleanup() {
    unsafe { handler::HANDLER.cleanup() }
}

#[no_mangle]
pub extern "C" fn parasite_daemon_cmd(cmd: c_int, args: *mut c_void) -> c_int {
    unsafe {
        let ret = handler::HANDLER.daemon_cmd(cmd as u32, *(args as *mut _));
        *(args as *mut _) = ret;
    }
    0
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("parasite panic: {:?}", info);
    unsafe {
        syscall!(syscalls::Sysno::exit, 1).ok();
    }
    loop {}
}
