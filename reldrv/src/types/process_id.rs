use std::{fmt::Display, ops::Range, sync::Arc};

use itertools::Itertools;
use log::{debug, error, info};

use crate::{
    dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressesWithFlags},
    error::Error,
    events::comparator::{
        MemoryComparator, MemoryComparsionResult, RegisterComparator, RegisterComparsionResult,
    },
    process::{
        dirty_pages::merge_page_addresses,
        registers::RegisterAccess,
        state::{ProcessState, Stopped, WithProcess},
        Process, PAGESIZE,
    },
    types::checker_status::CheckerStatus,
    utils::compare_memory::compare_memory,
};

use super::{checker_exec::CheckerExecution, checker_status::CheckFailReason, segment::Segment};

macro_rules! impl_maps {
    ($t:tt, $($f:ident),*) => {
        impl<S: ProcessState> $t<S> {
            pub fn map_process<F, R, S2: ProcessState>(mut self, f: F) -> ($t<S2>, R)
            where
                F: FnOnce(Process<S>) -> WithProcess<S2, R>,
            {
                let WithProcess(p2, r) = f(self.process.take().unwrap());

                (
                    $t {
                        process: Some(p2),
                        $(
                            $f: self.$f,
                        )*
                    },
                    r,
                )
            }

            pub fn try_map_process<F, R, E, S2: ProcessState>(
                mut self,
                f: F,
            ) -> Result<($t<S2>, R), E>
            where
                F: FnOnce(Process<S>) -> Result<WithProcess<S2, R>, E>,
            {
                let WithProcess(p2, r) = f(self.process.take().unwrap())?;

                Ok((
                    $t {
                        process: Some(p2),
                        $(
                            $f: self.$f,
                        )*
                    },
                    r,
                ))
            }

            pub fn try_map_process_noret<F, E, S2: ProcessState>(
                mut self,
                f: F,
            ) -> Result<$t<S2>, E>
            where
                F: FnOnce(Process<S>) -> Result<Process<S2>, E>,
            {
                let p2 = f(self.process.take().unwrap())?;

                Ok($t {
                    process: Some(p2),
                    $(
                        $f: self.$f,
                    )*
                })
            }

            pub fn try_map_process_inplace<F, R, E>(&mut self, f: F) -> Result<R, E>
            where
                F: FnOnce(Process<S>) -> Result<WithProcess<S, R>, E>,
            {
                let WithProcess(p2, r) = f(self.process.take().unwrap())?;

                self.process = Some(p2);
                Ok(r)
            }

            pub fn process(&self) -> &Process<S> {
                self.process.as_ref().unwrap()
            }

            pub fn process_mut(&mut self) -> &mut Process<S> {
                self.process.as_mut().unwrap()
            }
        }
    };
}

#[derive(Debug)]
pub struct Main<S: ProcessState> {
    pub process: Option<Process<S>>,
    pub segment: Option<Arc<Segment>>,
}

impl_maps!(Main, segment);

impl<S: ProcessState> Display for Main<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.segment.as_ref() {
            Some(segment) => write!(f, "[M{:>8}]", segment.nr),
            None => write!(f, "[M        ]"),
        }
    }
}

#[derive(Debug)]
pub struct Checker<S: ProcessState> {
    pub process: Option<Process<S>>,
    pub segment: Arc<Segment>,
    pub exec: Arc<CheckerExecution>,
}

impl_maps!(Checker, segment, exec);

impl Checker<Stopped> {
    fn compare_memory(
        id: &InferiorId,
        dpa_main: &DirtyPageAddressesWithFlags,
        dpa_checker: &DirtyPageAddressesWithFlags,
        mut checker_process: Process<Stopped>,
        mut reference_process: Process<Stopped>,
        ignored_pages: &[usize],
        _extra_writable_ranges: &[Range<usize>],
        comparator: &dyn MemoryComparator,
    ) -> crate::error::Result<(Process<Stopped>, Process<Stopped>, Option<CheckFailReason>)> {
        let dpa_merged = merge_page_addresses(
            &dpa_main.addresses,
            &dpa_checker.addresses,
            &ignored_pages
                .iter()
                .map(|&x| x..x + *PAGESIZE)
                .collect_vec(),
        );

        let checker_writable_ranges = checker_process.get_writable_ranges()?;
        let reference_writable_ranges = reference_process.get_writable_ranges()?;

        if checker_writable_ranges != reference_writable_ranges {
            error!("{id}: Memory map differs for epoch");
            return Ok((
                checker_process,
                reference_process,
                Some(CheckFailReason::MemoryMapMismatch),
            ));
        }

        if !dpa_main.flags.contains_writable_only || !dpa_checker.flags.contains_writable_only {
            todo!();
        }

        debug!("{id} Comparing {} dirty pages", dpa_merged.len());

        let mut result;
        (checker_process, reference_process, result) =
            comparator.compare_memory(&dpa_merged, checker_process, reference_process)?;

        match result {
            MemoryComparsionResult::Pass => Ok((checker_process, reference_process, None)),
            MemoryComparsionResult::Fail { first_mismatch } => {
                if first_mismatch.is_none() {
                    debug!("{id} Unknown first mismatch, use the slow path to find out");
                    result = compare_memory(&checker_process, &reference_process, &dpa_merged)?;
                }

                assert!(matches!(
                    result,
                    MemoryComparsionResult::Fail {
                        first_mismatch: Some(_)
                    }
                ));

                error!("{id} {result}");

                error!(
                    "{id} Checker memory map:\n{}",
                    checker_process.dump_memory_maps()?
                );
                error!(
                    "{id} Reference memory map:\n{}",
                    reference_process.dump_memory_maps()?
                );

                return Ok((
                    checker_process,
                    reference_process,
                    Some(CheckFailReason::MemoryMismatch),
                ));
            }
        }
    }

    fn compare_registers<C: RegisterAccess, R: RegisterAccess>(
        id: &InferiorId,
        checker_process: C,
        reference_process: R,
        comparator: &dyn RegisterComparator,
    ) -> crate::error::Result<(C, R, Option<CheckFailReason>)> {
        let (checker_process, mut checker_regs) = checker_process.read_registers_precisely()?;
        checker_regs = checker_regs.strip_orig().with_resume_flag_cleared();

        let (reference_process, mut reference_regs) =
            reference_process.read_registers_precisely()?;
        reference_regs = reference_regs.strip_orig().with_resume_flag_cleared();

        let reg_cmp_result =
            comparator.compare_registers(&mut checker_regs, &mut reference_regs)?;

        let result = match reg_cmp_result {
            RegisterComparsionResult::NoResult => {
                if checker_regs != reference_regs {
                    error!("{id} Register differs");
                    error!("{id} Checker registers:\n{}", checker_regs.dump());
                    error!("{id} Reference registers:\n{}", reference_regs.dump());

                    Some(CheckFailReason::RegisterMismatch)
                } else {
                    None
                }
            }
            RegisterComparsionResult::Pass => None,
            RegisterComparsionResult::Fail => Some(CheckFailReason::RegisterMismatch),
        };

        Ok((checker_process, reference_process, result))
    }

    pub fn check(
        &mut self,
        ignored_pages: &[usize],
        extra_writable_ranges: &[Range<usize>],
        dirty_page_tracker: &dyn DirtyPageAddressTracker,
        register_comparator: &dyn RegisterComparator,
        memory_comparator: &dyn MemoryComparator,
    ) -> crate::error::Result<Option<CheckFailReason>> {
        let id = self.into();
        info!("{id} Checking");

        self.segment.wait_until_main_finished()?;

        let dpa_main = self
            .segment
            .get_main_dirty_page_addresses_once(dirty_page_tracker, extra_writable_ranges)?;

        let dpa_checker = Arc::new(
            dirty_page_tracker.take_dirty_pages_addresses(self.into(), extra_writable_ranges)?,
        );

        debug!("{id} Main dirty pages: {}", dpa_main.nr_dirty_pages());
        debug!("{id} Checker dirty pages: {}", dpa_checker.nr_dirty_pages());

        let result = (|| {
            let checkpoint_end = self
                .segment
                .checkpoint_end()
                .expect("Invalid segment status");

            let mut ref_process_mg = checkpoint_end.process.lock();
            let mut ref_process = ref_process_mg.take().unwrap();

            let result;
            (ref_process, result) = self.try_map_process_inplace(|chk_process| {
                let WithProcess(ref_process, (chk_process, result)) =
                    ref_process.try_borrow_with(|ref_process_attached| {
                        let (chk_process, ref_process_attached, result) = Self::compare_registers(
                            &id,
                            chk_process,
                            ref_process_attached,
                            register_comparator,
                        )?;

                        if let Some(reason) = result {
                            return Ok(WithProcess(
                                ref_process_attached,
                                (chk_process, Some(reason)),
                            ));
                        }

                        let (chk_process, ref_process_attached, result) = Self::compare_memory(
                            &id,
                            &dpa_main,
                            &dpa_checker,
                            chk_process,
                            ref_process_attached,
                            ignored_pages,
                            extra_writable_ranges,
                            memory_comparator,
                        )?;

                        Ok(WithProcess(ref_process_attached, (chk_process, result)))
                    })?;

                Ok::<_, crate::error::Error>(WithProcess(chk_process, (ref_process, result)))
            })?;

            *ref_process_mg = Some(ref_process);

            Ok::<_, Error>(result)
        })()?;

        *self.exec.status.lock() = CheckerStatus::Checked {
            result,
            dirty_page_addresses: dpa_checker,
        };

        Ok(result)
    }
}

impl<S: ProcessState> Display for Checker<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[C{:>6}/{}]", self.segment.nr, self.exec.id)
    }
}

#[derive(Debug)]
pub enum Inferior<S: ProcessState> {
    Main(Main<S>),
    Checker(Checker<S>),
}

impl<S: ProcessState> Inferior<S> {
    pub fn is_main(&self) -> bool {
        matches!(self, Inferior::Main { .. })
    }

    pub fn is_checker(&self) -> bool {
        matches!(self, Inferior::Checker { .. })
    }

    pub fn unwrap_main(&self) -> &Main<S> {
        match self {
            Inferior::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_main_mut(&mut self) -> &mut Main<S> {
        match self {
            Inferior::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker(&self) -> &Checker<S> {
        match self {
            Inferior::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker_mut(&mut self) -> &mut Checker<S> {
        match self {
            Inferior::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn process(&self) -> &Process<S> {
        match self {
            Inferior::Main(main) => &main.process.as_ref().unwrap(),
            Inferior::Checker(checker) => checker.process.as_ref().unwrap(),
        }
    }

    pub fn process_mut(&mut self) -> &mut Process<S> {
        match self {
            Inferior::Main(main) => main.process.as_mut().unwrap(),
            Inferior::Checker(checker) => checker.process.as_mut().unwrap(),
        }
    }

    pub fn segment(&self) -> Option<&Arc<Segment>> {
        match self {
            Inferior::Main(main) => main.segment.as_ref(),
            Inferior::Checker(checker) => Some(&checker.segment),
        }
    }

    pub fn take_process(&mut self) -> Process<S> {
        match self {
            Inferior::Main(main) => main.process.take().unwrap(),
            Inferior::Checker(checker) => checker.process.take().unwrap(),
        }
    }

    pub fn id(&self) -> InferiorId {
        match self {
            Inferior::Main(main) => InferiorId::Main(main.segment.clone()),
            Inferior::Checker(checker) => {
                InferiorId::Checker(checker.segment.clone(), checker.exec.clone())
            }
        }
    }

    pub fn try_map_process<S2: ProcessState, E, R>(
        self,
        f: impl FnOnce(Process<S>) -> std::result::Result<WithProcess<S2, R>, E>,
    ) -> std::result::Result<(Inferior<S2>, R), E> {
        match self {
            Inferior::Main(main) => {
                let (p2, r) = main.try_map_process(f)?;
                Ok((Inferior::Main(p2), r))
            }
            Inferior::Checker(checker) => {
                let (p2, r) = checker.try_map_process(f)?;
                Ok((Inferior::Checker(p2), r))
            }
        }
    }

    pub fn try_map_process_noret<S2: ProcessState, E>(
        self,
        f: impl FnOnce(Process<S>) -> std::result::Result<Process<S2>, E>,
    ) -> std::result::Result<Inferior<S2>, E> {
        match self {
            Inferior::Main(main) => Ok(Inferior::Main(main.try_map_process_noret(f)?)),
            Inferior::Checker(checker) => Ok(Inferior::Checker(checker.try_map_process_noret(f)?)),
        }
    }

    pub fn try_map_process_inplace<E, R>(
        &mut self,
        f: impl FnOnce(Process<S>) -> std::result::Result<WithProcess<S, R>, E>,
    ) -> std::result::Result<R, E> {
        match self {
            Inferior::Main(main) => main.try_map_process_inplace(f),
            Inferior::Checker(checker) => checker.try_map_process_inplace(f),
        }
    }
}

impl<S: ProcessState> Display for Inferior<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Main(main) => main.fmt(f),
            Self::Checker(checker) => checker.fmt(f),
        }
    }
}

impl<S: ProcessState> From<Main<S>> for Inferior<S> {
    fn from(value: Main<S>) -> Self {
        Self::Main(value)
    }
}

impl<S: ProcessState> From<Checker<S>> for Inferior<S> {
    fn from(value: Checker<S>) -> Self {
        Self::Checker(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InferiorId {
    Main(Option<Arc<Segment>>),
    Checker(Arc<Segment>, Arc<CheckerExecution>),
}

impl InferiorId {
    pub fn segment(&self) -> Option<Arc<Segment>> {
        match self {
            Self::Main(segment) => segment.clone(),
            Self::Checker(segment, _) => Some(segment.clone()),
        }
    }
}

impl<S: ProcessState> From<&Main<S>> for InferiorId {
    fn from(value: &Main<S>) -> Self {
        Self::Main(value.segment.clone())
    }
}

impl<S: ProcessState> From<&Checker<S>> for InferiorId {
    fn from(value: &Checker<S>) -> Self {
        Self::Checker(value.segment.clone(), value.exec.clone())
    }
}

impl<S: ProcessState> From<&Inferior<S>> for InferiorId {
    fn from(value: &Inferior<S>) -> Self {
        value.id()
    }
}

impl<S: ProcessState> From<&mut Main<S>> for InferiorId {
    fn from(value: &mut Main<S>) -> Self {
        Self::Main(value.segment.clone())
    }
}

impl<S: ProcessState> From<&mut Checker<S>> for InferiorId {
    fn from(value: &mut Checker<S>) -> Self {
        Self::Checker(value.segment.clone(), value.exec.clone())
    }
}

impl<S: ProcessState> From<&mut Inferior<S>> for InferiorId {
    fn from(value: &mut Inferior<S>) -> Self {
        value.id()
    }
}

impl<'a, S: ProcessState> From<&mut InferiorRefMut<'a, S>> for InferiorId {
    fn from(value: &mut InferiorRefMut<S>) -> Self {
        value.id()
    }
}

impl Display for InferiorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InferiorId::Main(Some(main)) => write!(f, "[M{:>8}]", main.nr),
            InferiorId::Main(None) => write!(f, "[M        ]"),
            InferiorId::Checker(checker, exec) => write!(f, "[C{:>6}/{}]", checker.nr, exec.id),
        }
    }
}

pub enum InferiorRefMut<'a, S: ProcessState> {
    Main(&'a mut Main<S>),
    Checker(&'a mut Checker<S>),
}

impl<'a, S: ProcessState> From<&'a mut Inferior<S>> for InferiorRefMut<'a, S> {
    fn from(value: &'a mut Inferior<S>) -> Self {
        match value {
            Inferior::Main(main) => InferiorRefMut::Main(main),
            Inferior::Checker(checker) => InferiorRefMut::Checker(checker),
        }
    }
}

impl<'a, S: ProcessState> From<&'a mut Main<S>> for InferiorRefMut<'a, S> {
    fn from(value: &'a mut Main<S>) -> Self {
        InferiorRefMut::Main(value)
    }
}

impl<'a, S: ProcessState> From<&'a mut Checker<S>> for InferiorRefMut<'a, S> {
    fn from(value: &'a mut Checker<S>) -> Self {
        InferiorRefMut::Checker(value)
    }
}

impl<'a, S: ProcessState> InferiorRefMut<'a, S> {
    pub fn copied(&'a mut self) -> Self {
        match self {
            InferiorRefMut::Main(main) => InferiorRefMut::Main(main),
            InferiorRefMut::Checker(checker) => InferiorRefMut::Checker(checker),
        }
    }

    pub fn is_main(&self) -> bool {
        matches!(self, InferiorRefMut::Main { .. })
    }

    pub fn is_checker(&self) -> bool {
        matches!(self, InferiorRefMut::Checker { .. })
    }

    pub fn unwrap_main(&self) -> &Main<S> {
        match self {
            InferiorRefMut::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_main_mut(&mut self) -> &mut Main<S> {
        match self {
            InferiorRefMut::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker(&self) -> &Checker<S> {
        match self {
            InferiorRefMut::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker_mut(&mut self) -> &mut Checker<S> {
        match self {
            InferiorRefMut::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn process(&self) -> &Process<S> {
        match self {
            InferiorRefMut::Main(main) => main.process.as_ref().unwrap(),
            InferiorRefMut::Checker(checker) => checker.process.as_ref().unwrap(),
        }
    }

    pub fn process_mut(&mut self) -> &mut Process<S> {
        match self {
            InferiorRefMut::Main(main) => main.process.as_mut().unwrap(),
            InferiorRefMut::Checker(checker) => checker.process.as_mut().unwrap(),
        }
    }

    pub fn id(&self) -> InferiorId {
        match self {
            InferiorRefMut::Main(main) => InferiorId::Main(main.segment.clone()),
            InferiorRefMut::Checker(checker) => {
                InferiorId::Checker(checker.segment.clone(), checker.exec.clone())
            }
        }
    }

    pub fn role(&self) -> InferiorRole {
        self.into()
    }

    pub fn segment(&self) -> Option<Arc<Segment>> {
        match self {
            InferiorRefMut::Main(main) => main.segment.clone(),
            InferiorRefMut::Checker(checker) => Some(checker.segment.clone()),
        }
    }

    pub fn try_map_process_inplace<E, R>(
        &mut self,
        f: impl FnOnce(Process<S>) -> std::result::Result<WithProcess<S, R>, E>,
    ) -> std::result::Result<R, E> {
        match self {
            InferiorRefMut::Main(main) => main.try_map_process_inplace(f),
            InferiorRefMut::Checker(checker) => checker.try_map_process_inplace(f),
        }
    }

    pub fn try_map_process_inplace_noret<E>(
        &mut self,
        f: impl FnOnce(Process<S>) -> std::result::Result<Process<S>, E>,
    ) -> std::result::Result<(), E> {
        self.try_map_process_inplace(|p| f(p).map(|r| r.with_ret(())))?;
        Ok(())
    }
}

impl<S: ProcessState> Display for InferiorRefMut<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Main(main) => main.fmt(f),
            Self::Checker(checker) => checker.fmt(f),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InferiorRole {
    Main,
    Checker(Arc<Segment>),
}

impl<S: ProcessState> From<&InferiorRefMut<'_, S>> for InferiorRole {
    fn from(value: &InferiorRefMut<S>) -> Self {
        match value {
            InferiorRefMut::Main(_) => InferiorRole::Main,
            InferiorRefMut::Checker(checker) => InferiorRole::Checker(checker.segment.clone()),
        }
    }
}

impl Display for InferiorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InferiorRole::Main => write!(f, "[M       ?]"),
            InferiorRole::Checker(segment) => write!(f, "[C{:>6}/?]", segment.nr),
        }
    }
}
