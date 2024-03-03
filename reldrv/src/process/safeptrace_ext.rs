// use crate::error::Result;

// use nix::sys::ptrace::{self, SyscallInfoOp};
// use safeptrace::{Stopped, Pid};
// use syscalls::{SyscallArgs, Sysno};

// use super::registers::Registers;

// fn save_state(pid: Pid) -> Result<(Registers, u64)> {
//     Ok((
//         Registers::new(ptrace::getregs(pid)?),
//         ptrace::getsigmask(pid)?,
//     ))
// }

// trait SyscallInjectionExt
// where
//     Self: Sized,
// {
//     fn inject_syscall(
//         self,
//         sysno: Sysno,
//         args: SyscallArgs,
//         restart_parent_old_syscall: bool,
//         restart_child_old_syscall: bool,
//         force_instr_insertion: bool,
//     ) -> Result<(Self, i64)>;
// }

// impl SyscallInjectionExt for Stopped {
//     fn inject_syscall(
//         self,
//         sysno: Sysno,
//         args: SyscallArgs,
//         restart_parent_old_syscall: bool,
//         restart_child_old_syscall: bool,
//         force_instr_insertion: bool,
//     ) -> Result<(Self, i64)> {
//         let pid = self.pid();

//                 // save the old states
//                 let (saved_regs, saved_sigmask) = save_state(pid)?;
//                 let mut saved_instr = None;
        
//                 let mut op = ptrace::getsyscallinfo(pid)?.op;
//                 if force_instr_insertion {
//                     op = SyscallInfoOp::None;
//                 }
        
//                 match op {
//                     SyscallInfoOp::Entry { .. } => (),
//                     SyscallInfoOp::Exit { .. } => {
//                         // never restart old syscalls on exit
//                         restart_child_old_syscall = false;
//                         restart_parent_old_syscall = false;
        
//                         // handle syscall exit
//                         assert_eq!(self.instr_at(saved_regs.rip as usize - 2, 2), 0x050f); // syscall
        
//                         self.write_registers(saved_regs.with_offsetted_rip(-2))?; // jump back to previous syscall
//                         ptrace::syscall(pid, None)?;
        
//                         assert!(matches!(
//                             waitpid(pid, None)?,
//                             WaitStatus::PtraceSyscall(_)
//                         ));
        
//                         assert!(matches!(
//                             ptrace::getsyscallinfo(pid)?.op,
//                             SyscallInfoOp::Entry { .. }
//                         ));
//                     }
//                     SyscallInfoOp::None => {
//                         // insert an ad-hoc syscall instruction
//                         restart_child_old_syscall = false;
//                         restart_parent_old_syscall = false;
        
//                         let addr = saved_regs.rip & (!(*PAGESIZE - 1));
//                         let orig_instr = self.instr_at(addr as usize, 2) as u16;
        
//                         saved_instr = Some((addr, orig_instr));
        
//                         // dbg!(saved_instr);
        
//                         // info!("Addr {:p}", addr as *const u8);
//                         // self.dump_memory_maps().unwrap();
        
//                         let orig_word = ptrace::read(pid, addr as *mut c_void).unwrap() as u64;
        
//                         let new_word = (orig_word & (!0xffff)) | 0x050f;
        
//                         unsafe { ptrace::write(pid, addr as *mut c_void, new_word as *mut c_void) }
//                             .unwrap();
        
//                         self.write_registers(saved_regs.with_rip(addr))?;
        
//                         ptrace::syscall(pid, None)?;
        
//                         assert!(matches!(
//                             waitpid(pid, None)?,
//                             WaitStatus::PtraceSyscall(_)
//                         ));
        
//                         assert!(matches!(
//                             ptrace::getsyscallinfo(pid)?.op,
//                             SyscallInfoOp::Entry { .. }
//                         ));
//                     }
//                     _ => panic!(),
//                 };
        
//                 // prepare the injected syscall number and arguments
//                 self.write_registers(saved_regs.with_sysno(nr).with_syscall_args(args))?;
        
//                 // block signals during our injected syscall
//                 ptrace::setsigmask(pid, !0)?;
        
//                 // execute our injected syscall
//                 ptrace::syscall(pid, None)?;
        
//                 // expect the syscall event
//                 let mut wait_status = waitpid(pid, None)?;
        
//                 // handle fork/clone event
//                 let child_pid = if let WaitStatus::PtraceEvent(pid, _sig, event) = wait_status {
//                     let child_pid = Pid::from_raw(match event {
//                         nix::libc::PTRACE_EVENT_CLONE | nix::libc::PTRACE_EVENT_FORK => {
//                             ptrace::getevent(pid)? as _
//                         }
//                         _ => panic!("Unexpected ptrace event received"),
//                     });
        
//                     ptrace::syscall(pid, None)?;
//                     wait_status = waitpid(pid, None)?;
//                     Some(child_pid)
//                 } else {
//                     None
//                 };
        
//                 assert_eq!(wait_status, WaitStatus::PtraceSyscall(pid));
        
//                 // get the syscall return value
//                 let syscall_info = ptrace::getsyscallinfo(pid)?;
//                 let syscall_ret = if let SyscallInfoOp::Exit { ret_val, .. } = syscall_info.op {
//                     ret_val
//                 } else {
//                     panic!("Unexpected syscall info: {:?}", syscall_info);
//                 };
        
//                 Self::restore_state(
//                     pid,
//                     saved_regs,
//                     saved_sigmask,
//                     restart_parent_old_syscall,
//                     saved_instr,
//                 )?;
        
//                 if let Some(child_pid) = child_pid {
//                     let wait_status = waitpid(child_pid, None)?;
//                     assert!(
//                         matches!(wait_status, WaitStatus::PtraceEvent(pid, sig, _ev) if pid == child_pid && sig == Signal::SIGTRAP)
//                     );
        
//                     Self::restore_state(
//                         child_pid,
//                         saved_regs,
//                         saved_sigmask,
//                         restart_child_old_syscall,
//                         saved_instr,
//                     )?;
//                 }
        
//                 Ok(syscall_ret)
        
//         todo!()
//     }
// }

// trait ProcessCloneExt: SyscallInjectionExt // where Self: Sized,
// {
//     fn clone_process(self) -> Result<()>;
// }
