use core::fmt::{Error, Result, Write};

use syscalls::{syscall, Sysno};

pub struct FdOut<const FD: usize>;

pub static mut STDOUT: FdOut<1> = FdOut;
pub static mut STDERR: FdOut<2> = FdOut;

impl<const FD: usize> Write for FdOut<FD> {
    fn write_str(&mut self, s: &str) -> Result {
        unsafe {
            syscall!(Sysno::write, FD, s.as_ptr(), s.len())
                .map(|_| ())
                .map_err(|_| Error {})
        }
    }
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        core::write!(unsafe { &mut $crate::log::STDERR }, $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        core::writeln!(unsafe { &mut $crate::log::STDERR }, $($arg)*).ok();
    }};
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        core::write!(unsafe { &mut $crate::log::STDOUT }, $($arg)*);
    }};
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        core::writeln!(unsafe { &mut $crate::log::STDOUT }, $($arg)*).ok();
    }};
}
