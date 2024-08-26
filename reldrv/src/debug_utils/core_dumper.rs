use std::{os::unix::fs::symlink, path::PathBuf, process::Command};

use log::{error, info};
use nix::unistd::Pid;
use path_macro::path;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::segment::SegmentEventHandler,
    process::state::Stopped,
    types::{checker::CheckFailReason, process_id::Checker},
};

pub struct CoreDumper {
    gcore_bin: PathBuf,
    output_dir: PathBuf,
}

fn dump_process(gcore: &PathBuf, pid: Pid, filename: &PathBuf) -> Result<()> {
    info!("Dumping PID {} to {}", pid, filename.display());
    let exit_status = Command::new(gcore)
        .arg("-o")
        .arg(filename)
        .arg(pid.as_raw().to_string())
        .spawn()?
        .wait()?;
    if !exit_status.success() {
        error!("gcore failed with exit status: {}", exit_status);
    }
    Ok(())
}

impl CoreDumper {
    pub fn new(gcore_bin: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            gcore_bin,
            output_dir,
        }
    }
}

impl SegmentEventHandler for CoreDumper {
    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
        check_fail_reason: &Option<CheckFailReason>,
    ) -> Result<()> {
        if check_fail_reason.is_some() {
            info!("Creating core dump");
            let child = checker.try_map_process_inplace(|p| p.fork(true, true))?;

            let p = child.detach()?;
            dump_process(
                &self.gcore_bin,
                p.pid,
                &path!(self.output_dir / format!("checker_{}.core", checker.segment.nr)),
            )?;
            drop(p);

            let p = checker.segment.reference_start();
            dump_process(
                &self.gcore_bin,
                p.pid,
                &path!(self.output_dir / format!("ckpt_start_{}.core", checker.segment.nr)),
            )?;
            drop(p);

            if let Some(ref_end) = checker.segment.status.lock().checkpoint_end() {
                let p = ref_end.process.lock();
                dump_process(
                    &self.gcore_bin,
                    p.as_ref().unwrap().pid,
                    &path!(self.output_dir / format!("ckpt_end_{}.core", checker.segment.nr)),
                )?;
                drop(p);
            }

            let exe = checker.process().procfs()?.exe()?;
            match symlink(&exe, &path!(self.output_dir / "exe")) {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(e),
            }?;
        }

        Ok(())
    }
}

impl Module for CoreDumper {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
    }
}
