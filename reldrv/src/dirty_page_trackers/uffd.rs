use std::{
    collections::HashMap,
    fs::OpenOptions,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    sync::Arc,
    usize,
};

use log::debug;
use parking_lot::Mutex;
use path_macro::path;
use syscalls::syscall_args;
use userfaultfd::{RegisterMode, Uffd};

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        segment::SegmentEventHandler,
    },
    process::{dirty_pages::PageFlag, Process},
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
        syscall_args!(0),
        true,
        true,
        false,
    )?;

    if remote_fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-remote_fd as _).into());
    }

    let fd = OpenOptions::new().read(true).write(true).open(path!(
        "/proc" / process.pid.to_string() / "fd" / remote_fd.to_string()
    ))?;

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
    ) -> Result<DirtyPageAddressesWithFlags> {
        let pages = match &inferior_id {
            InferiorId::Main(segment) => segment
                .as_ref()
                .unwrap()
                .checkpoint_end()
                .unwrap()
                .process
                .lock()
                .get_dirty_pages(PageFlag::UffdWp)?,
            InferiorId::Checker(segment) => {
                let pid = segment.checker_status.lock().pid().unwrap();
                Process::new(pid).get_dirty_pages(PageFlag::UffdWp)?
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

impl ProcessLifetimeHook for UffdDirtyPageTracker {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        let uffd = create_uffd(&context.process)?;
        debug!("Registering UFFD for process {}", context.process.pid);
        uffd.register_with_mode(0 as _, usize::MAX, RegisterMode::WRITE_PROTECT)?;

        *self.main_uffd.lock() = Some(uffd);

        Ok(())
    }
}

impl SegmentEventHandler for UffdDirtyPageTracker {
    fn handle_checkpoint_created_pre(&self, _main: &mut Main) -> Result<()> {
        if !self.dont_clear_dirty {
            self.main_uffd
                .lock()
                .as_ref()
                .unwrap()
                .write_protect(0 as _, usize::MAX)?;
        }
        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker) -> Result<()> {
        let uffd = create_uffd(&checker.process)?;
        uffd.register_with_mode(0 as _, usize::MAX, RegisterMode::WRITE_PROTECT)?;
        if !self.dont_clear_dirty {
            uffd.write_protect(0 as _, usize::MAX)?;
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

impl Module for UffdDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
        subs.install_segment_event_handler(self);
        subs.install_process_lifetime_hook(self);
    }
}
