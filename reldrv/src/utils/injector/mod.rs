use std::{mem::size_of, slice};

use itertools::repeat_n;
use log::{debug, info};
use nix::sys::{
    mman::{MapFlags, ProtFlags},
    wait::WaitStatus,
};
use reverie_syscalls::{Displayable, MemoryAccess, Syscall};
use syscalls::Sysno;

use crate::{
    error::Result,
    process::{
        registers::RegisterAccess,
        state::{Stopped, WithProcess},
        Process, SyscallDir, PAGESIZE,
    },
};

const STACK_SIZE: usize = 0x2000;
const ALIGN: usize = 16;

fn allocate_buf(buf: &mut Vec<u8>, data: &[u8]) -> usize {
    let size = data.len();
    let real_size = size.next_multiple_of(ALIGN);

    let start = buf.len();
    buf.extend(data);
    buf.extend(repeat_n(0, real_size - size));

    start
}

fn allocate<T>(buf: &mut Vec<u8>, data: &T) -> usize {
    let size = std::mem::size_of::<T>();
    let real_size = size.next_multiple_of(ALIGN);

    let start = buf.len();
    buf.extend(unsafe { slice::from_raw_parts(data as *const T as *const u8, size) });
    buf.extend(repeat_n(0, real_size - size));

    start
}

fn allocate_zeros(buf: &mut Vec<u8>, size: usize) -> usize {
    let real_size = size.next_multiple_of(ALIGN);

    let start = buf.len();
    buf.extend(repeat_n(0, real_size));

    start
}

pub unsafe fn inject_and_run<T, R>(
    binary: &[u8],
    arg: &T,
    mut process: Process<Stopped>,
) -> Result<WithProcess<Stopped, R>> {
    let mut buf = Vec::new();

    let bin_addr = allocate_buf(&mut buf, binary);
    let arg_addr = allocate(&mut buf, arg);
    let out_addr = allocate_zeros(&mut buf, size_of::<R>());
    let stack_addr = allocate_zeros(&mut buf, STACK_SIZE);

    let base_addr;
    WithProcess(process, base_addr) = process.mmap(
        0,
        buf.len().next_multiple_of(*PAGESIZE),
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
    )?;
    let base_addr = base_addr?;

    let syscall_ctx;
    WithProcess(process, syscall_ctx) = process.save_syscall_context_and_reg()?;

    process.write_exact(base_addr.into(), &buf)?;

    process.modify_registers_with(|r| {
        r.with_sp(
            base_addr + stack_addr + STACK_SIZE, /* stack grows down */
        )
        .with_ip(base_addr + bin_addr)
        .with_arg0(base_addr + arg_addr)
        .with_arg1(base_addr + out_addr)
    })?;

    debug!("Starting parasite");
    let mut process_running = process.resume()?;

    loop {
        let status;
        WithProcess(process, status) = process_running.waitpid()?.unwrap_stopped();

        match status {
            WaitStatus::PtraceSyscall(_) => {
                let regs = process.read_registers()?;
                let syscall_dir = process.syscall_dir()?;

                if syscall_dir == SyscallDir::Entry {
                    info!(
                        "Parasite syscall: {}",
                        Syscall::from_raw(regs.sysno().unwrap(), regs.syscall_args())
                            .display(&process)
                    );
                }

                if syscall_dir == SyscallDir::Entry && regs.sysno() == Some(Sysno::rt_sigreturn) {
                    debug!("Parasite finished");
                    process.modify_registers_with(|r| r.with_syscall_skipped())?;
                    let status;
                    WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
                    assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
                    debug_assert_eq!(process.syscall_dir()?, SyscallDir::Exit);
                    break;
                }
            }
            WaitStatus::Exited(_, _) => panic!("Process exited unexpectedly"),
            WaitStatus::Signaled(_, sig, _) => panic!("Process unexpectedly signaled with {}", sig),
            WaitStatus::Stopped(_, sig) => {
                info!("Parasite signal: {}", sig);
                process_running = process.resume_with_signal(sig)?;
                continue;
            }
            _ => (),
        }

        process_running = process.resume()?;
    }

    process = process.restore_syscall_context_and_reg(syscall_ctx)?;

    let out: R = process.read_value(base_addr + out_addr)?;

    let result;
    WithProcess(process, result) =
        process.munmap(base_addr, buf.len().next_multiple_of(*PAGESIZE))?;
    result?;

    Ok(WithProcess(process, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::{init_logging, ptraced};

    use std::{io::IoSlice, mem::size_of_val};

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_inject_and_run_adder() -> crate::error::Result<()> {
        let mut process = ptraced(|| 0);

        // Add one to the value at x0 and store it in x1
        let binary: [u32; 6] = [
            0xf9400002, /* ldr x2, [x0] */
            0x91000442, /* add x2, x2, #1 */
            0xf9000022, /* str x2, [x1] */
            0x52801168, /* mov w8, #139 */
            0xd4000001, /* svc #0 */
            0xd4200000, /* brk #0 */
        ];

        let binary = unsafe {
            slice::from_raw_parts(&binary as *const _ as *const u8, size_of_val(&binary))
        };

        let result;
        WithProcess(process, result) =
            unsafe { inject_and_run::<_, u64>(binary, &42_u64, process)? };

        assert_eq!(result, 43);

        let status;
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }

    #[test]
    fn test_inject_and_run_hasher() -> crate::error::Result<()> {
        init_logging();

        #[repr(C)]
        struct HasherArgs {
            iovecs: *const IoSlice<'static>,
            len: usize,
        }

        let mut process = ptraced(|| 0);

        dbg!(process.pid);

        let binary = include_bytes!(concat!(env!("OUT_DIR"), "/hasher.bin"));

        let data: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

        let data_addr;
        WithProcess(process, data_addr) = process.mmap(
            0,
            data.len().next_multiple_of(*PAGESIZE),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )?;
        let data_addr = data_addr?;

        process.write_values(data_addr.into(), &data)?;

        let addresses =
            [IoSlice::new(unsafe { slice::from_raw_parts(data_addr as *const u8, data.len()) }); 3];

        let addresses_addr;
        WithProcess(process, addresses_addr) = process.mmap(
            0,
            (addresses.len() * size_of::<IoSlice>()).next_multiple_of(*PAGESIZE),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
        )?;
        let addresses_addr = addresses_addr?;

        process.write_values(addresses_addr.into(), &addresses)?;

        let args = HasherArgs {
            iovecs: addresses_addr as *const _,
            len: addresses.len(),
        };

        let result;
        WithProcess(process, result) = unsafe { inject_and_run::<_, u64>(binary, &args, process)? };

        assert_eq!(result, 0xb625b1186286445a);

        let status;
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }
}
