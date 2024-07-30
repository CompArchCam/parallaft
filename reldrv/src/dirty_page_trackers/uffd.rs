// TODO: track new memory mappings

use std::{
    collections::HashMap,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    sync::Arc,
};

use log::debug;
use parking_lot::Mutex;
use pidfd_getfd::{GetFdFlags, PidFdExt};
use procfs::process::{MMPermissions, MMapPath, MemoryMap};
use reverie_syscalls::Syscall;
use syscalls::syscall_args;
use try_insert_ext::OptionInsertExt;
use userfaultfd::{RegisterMode, Uffd};

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        segment::SegmentEventHandler,
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::{dirty_pages::PageFlag, Process},
    syscall_handlers::is_execve_ok,
    types::{
        process_id::{Checker, InferiorId, Main},
        segment::{Segment, SegmentId},
    },
};

use super::{DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressesWithFlags};

fn create_uffd(process: &Process) -> Result<Uffd> {
    debug!("Creating UFFD for process {}", process.pid);
    use userfaultfd::raw;

    let remote_fd = process.syscall_direct(
        syscalls::Sysno::userfaultfd,
        syscall_args!(nix::libc::O_CLOEXEC as _),
        true,
        true,
        true,
    )?;

    if remote_fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-remote_fd as _).into());
    }

    debug!("UFFD created with remote fd {}", remote_fd);

    let pfd = unsafe { pidfd::PidFd::open(process.pid.as_raw(), 0)? };

    let fd = pfd.get_file(remote_fd as _, GetFdFlags::empty())?;

    let mut api = raw::uffdio_api {
        api: raw::UFFD_API,
        features: raw::UFFD_FEATURE_WP_ASYNC,
        ioctls: 0,
    };
    unsafe {
        raw::api(fd.as_raw_fd(), &mut api as *mut raw::uffdio_api).expect("UFFDIO_API ioctl");
    }

    let uffd = unsafe { Uffd::from_raw_fd(fd.into_raw_fd()) };
    Ok(uffd)
}

fn for_each_writable_map(process: &Process, f: impl Fn(&MemoryMap) -> Result<()>) -> Result<()> {
    let maps = process.procfs()?.maps()?;

    for map in maps {
        if map.perms.contains(MMPermissions::WRITE)
            && ![MMapPath::Vdso, MMapPath::Vsyscall, MMapPath::Vvar].contains(&map.pathname)
        {
            f(&map)?;
        }
    }

    Ok(())
}

fn register_uffd(uffd: &Uffd, process: &Process) -> Result<()> {
    for_each_writable_map(process, |map| {
        uffd.register_with_mode(
            map.address.0 as _,
            (map.address.1 - map.address.0) as _,
            RegisterMode::WRITE_PROTECT,
        )
        .expect("UFFD registration failed");

        Ok(())
    })?;
    Ok(())
}

fn write_protect_uffd(uffd: &Uffd, process: &Process) -> Result<()> {
    for_each_writable_map(process, |map| {
        uffd.write_protect(map.address.0 as _, (map.address.1 - map.address.0) as _)
            .expect("UFFD WP failed");
        Ok(())
    })
}

pub struct UffdDirtyPageTracker {
    dont_clear_dirty: bool,
    main_uffd: Mutex<Option<Uffd>>,
    checker_uffds: Mutex<HashMap<SegmentId, Uffd>>,
}

impl UffdDirtyPageTracker {
    pub fn new(dont_clear_dirty: bool) -> Self {
        Self {
            dont_clear_dirty,
            main_uffd: Mutex::new(None),
            checker_uffds: Mutex::new(HashMap::new()),
        }
    }
}

impl DirtyPageAddressTracker for UffdDirtyPageTracker {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: InferiorId,
        extra_writable_ranges: &[std::ops::Range<usize>],
    ) -> Result<DirtyPageAddressesWithFlags> {
        let pages = match &inferior_id {
            InferiorId::Main(segment) => segment
                .as_ref()
                .unwrap()
                .checkpoint_end()
                .unwrap()
                .process
                .lock()
                .get_dirty_pages(PageFlag::UffdWp, extra_writable_ranges)?,
            InferiorId::Checker(segment) => {
                let pid = segment.checker_status.lock().pid().unwrap();
                Process::new(pid).get_dirty_pages(PageFlag::UffdWp, extra_writable_ranges)?
            }
        };

        Ok(DirtyPageAddressesWithFlags {
            addresses: Box::new(pages),
            flags: DirtyPageAddressFlags {
                contains_writable_only: true,
            },
        })
    }
}

impl SegmentEventHandler for UffdDirtyPageTracker {
    fn handle_checkpoint_created_pre(&self, main: &mut Main) -> Result<()> {
        if !self.dont_clear_dirty {
            let mut uffd_mg = self.main_uffd.lock();
            let uffd = uffd_mg.get_or_try_insert_with(|| create_uffd(&main.process))?;
            register_uffd(uffd, &main.process)?;
            write_protect_uffd(uffd, &main.process)?;
        }
        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker) -> Result<()> {
        let uffd = create_uffd(&checker.process)?;
        register_uffd(&uffd, &checker.process)?;
        if !self.dont_clear_dirty {
            write_protect_uffd(&uffd, &checker.process)?;
        }
        self.checker_uffds.lock().insert(checker.segment.nr, uffd);

        Ok(())
    }

    fn handle_segment_completed(&self, checker: &mut Checker) -> Result<()> {
        let mut checker_uffds = self.checker_uffds.lock();
        checker_uffds.remove(&checker.segment.nr);
        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        let mut checker_uffds = self.checker_uffds.lock();
        checker_uffds.remove(&segment.nr);
        Ok(())
    }
}

impl StandardSyscallHandler for UffdDirtyPageTracker {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        _context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            *self.main_uffd.lock() = None;
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    // TODO: handle mmap/mremap
}

impl Module for UffdDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
        subs.install_segment_event_handler(self);
        subs.install_standard_syscall_handler(self);
    }
}
