pub mod saved_memory;
pub mod saved_syscall;
pub mod saved_trap_event;

use std::sync::Arc;

use self::{
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    saved_trap_event::SavedTrapEvent,
};

#[derive(Debug)]
pub struct SegmentRecord {
    pub ongoing_syscall: Option<SavedIncompleteSyscall>,
    pub syscall_log: Vec<Arc<SavedSyscall>>,
    pub trap_event_log: Vec<Arc<SavedTrapEvent>>,
    pub syscall_pos: usize,
    pub trap_event_pos: usize,
}

impl Default for SegmentRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentRecord {
    pub fn new() -> Self {
        Self {
            syscall_log: Vec::new(),
            ongoing_syscall: None,
            trap_event_log: Vec::new(),
            syscall_pos: 0,
            trap_event_pos: 0,
        }
    }

    pub fn reset(&mut self) {
        self.syscall_pos = 0;
        self.trap_event_pos = 0;
    }

    pub fn peek_syscall(&self) -> Option<Arc<SavedSyscall>> {
        self.syscall_log.get(self.syscall_pos).cloned()
    }

    pub fn peek_trap_event(&self) -> Option<Arc<SavedTrapEvent>> {
        self.trap_event_log.get(self.trap_event_pos).cloned()
    }

    pub fn next_syscall(&mut self) -> Option<Arc<SavedSyscall>> {
        let ret = self.peek_syscall()?;
        self.syscall_pos += 1;
        Some(ret)
    }

    pub fn next_trap_event(&mut self) -> Option<Arc<SavedTrapEvent>> {
        let ret = self.peek_trap_event()?;
        self.trap_event_pos += 1;
        Some(ret)
    }

    pub fn push_syscall(&mut self, syscall: SavedSyscall) {
        self.syscall_log.push(Arc::new(syscall))
    }

    pub fn push_trap_event(&mut self, event: SavedTrapEvent) {
        self.trap_event_log.push(Arc::new(event))
    }
}
