use std::{fmt::Display, sync::Arc};

use crate::process::{
    state::{ProcessState, WithProcess},
    Process,
};

use super::segment::Segment;

macro_rules! impl_maps {
    ($t:tt) => {
        impl<S: ProcessState> $t<S> {
            pub fn map_process<F, R, S2: ProcessState>(mut self, f: F) -> ($t<S2>, R)
            where
                F: FnOnce(Process<S>) -> WithProcess<S2, R>,
            {
                let WithProcess(p2, r) = f(self.process.take().unwrap());

                (
                    $t {
                        process: Some(p2),
                        segment: self.segment,
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
                        segment: self.segment,
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
                    segment: self.segment,
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

impl_maps!(Main);

impl<S: ProcessState> Display for Main<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.segment.as_ref() {
            Some(segment) => write!(f, "[M{:>6}]", segment.nr),
            None => write!(f, "[M      ]"),
        }
    }
}

#[derive(Debug)]
pub struct Checker<S: ProcessState> {
    pub process: Option<Process<S>>,
    pub segment: Arc<Segment>,
}

impl_maps!(Checker);

impl<S: ProcessState> Display for Checker<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[C{:>6}]", self.segment.nr)
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
            Inferior::Checker(checker) => InferiorId::Checker(checker.segment.clone()),
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
    Checker(Arc<Segment>),
}

impl InferiorId {
    pub fn segment(&self) -> Option<Arc<Segment>> {
        match self {
            Self::Main(segment) => segment.clone(),
            Self::Checker(segment) => Some(segment.clone()),
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
        Self::Checker(value.segment.clone())
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
        Self::Checker(value.segment.clone())
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
            InferiorId::Main(Some(main)) => write!(f, "[M{:>6}]", main.nr),
            InferiorId::Main(None) => write!(f, "[M      ]"),
            InferiorId::Checker(checker) => write!(f, "[C{:>6}]", checker.nr),
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
            InferiorRefMut::Checker(checker) => InferiorId::Checker(checker.segment.clone()),
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
            InferiorRole::Main => write!(f, "[M     ?]"),
            InferiorRole::Checker(segment) => write!(f, "[C{:>6}]", segment.nr),
        }
    }
}
