use std::{fmt::Display, sync::Arc};

use crate::process::OwnedProcess;

use super::segment::Segment;

#[derive(Debug)]
pub struct Main {
    pub process: OwnedProcess,
    pub segment: Option<Arc<Segment>>,
}

impl Display for Main {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.segment.as_ref() {
            Some(segment) => write!(f, "[M{:>6}]", segment.nr),
            None => write!(f, "[M      ]"),
        }
    }
}

#[derive(Debug)]
pub struct Checker {
    pub process: OwnedProcess,
    pub segment: Arc<Segment>,
}

impl Display for Checker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[C{:>6}]", self.segment.nr)
    }
}

#[derive(Debug)]
pub enum Inferior {
    Main(Main),
    Checker(Checker),
}

impl Inferior {
    pub fn is_main(&self) -> bool {
        matches!(self, Inferior::Main { .. })
    }

    pub fn is_checker(&self) -> bool {
        matches!(self, Inferior::Checker { .. })
    }

    pub fn unwrap_main(&self) -> &Main {
        match self {
            Inferior::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_main_mut(&mut self) -> &mut Main {
        match self {
            Inferior::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker(&self) -> &Checker {
        match self {
            Inferior::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker_mut(&mut self) -> &mut Checker {
        match self {
            Inferior::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn process(&self) -> &OwnedProcess {
        match self {
            Inferior::Main(main) => &main.process,
            Inferior::Checker(checker) => &checker.process,
        }
    }

    pub fn process_mut(&mut self) -> &mut OwnedProcess {
        match self {
            Inferior::Main(main) => &mut main.process,
            Inferior::Checker(checker) => &mut checker.process,
        }
    }

    pub fn id(&self) -> InferiorId {
        match self {
            Inferior::Main(main) => InferiorId::Main(main.segment.clone()),
            Inferior::Checker(checker) => InferiorId::Checker(checker.segment.clone()),
        }
    }
}

impl Display for Inferior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Main(main) => main.fmt(f),
            Self::Checker(checker) => checker.fmt(f),
        }
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

impl From<&Main> for InferiorId {
    fn from(value: &Main) -> Self {
        Self::Main(value.segment.clone())
    }
}

impl From<&Checker> for InferiorId {
    fn from(value: &Checker) -> Self {
        Self::Checker(value.segment.clone())
    }
}

impl From<&Inferior> for InferiorId {
    fn from(value: &Inferior) -> Self {
        value.id()
    }
}

impl From<&mut Main> for InferiorId {
    fn from(value: &mut Main) -> Self {
        Self::Main(value.segment.clone())
    }
}

impl From<&mut Checker> for InferiorId {
    fn from(value: &mut Checker) -> Self {
        Self::Checker(value.segment.clone())
    }
}

impl From<&mut Inferior> for InferiorId {
    fn from(value: &mut Inferior) -> Self {
        value.id()
    }
}

pub enum InferiorRefMut<'a> {
    Main(&'a mut Main),
    Checker(&'a mut Checker),
}

impl<'a> From<&'a mut Inferior> for InferiorRefMut<'a> {
    fn from(value: &'a mut Inferior) -> Self {
        match value {
            Inferior::Main(main) => InferiorRefMut::Main(main),
            Inferior::Checker(checker) => InferiorRefMut::Checker(checker),
        }
    }
}

impl<'a> From<&'a mut Main> for InferiorRefMut<'a> {
    fn from(value: &'a mut Main) -> Self {
        InferiorRefMut::Main(value)
    }
}

impl<'a> From<&'a mut Checker> for InferiorRefMut<'a> {
    fn from(value: &'a mut Checker) -> Self {
        InferiorRefMut::Checker(value)
    }
}

impl<'a> InferiorRefMut<'a> {
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

    pub fn unwrap_main(&self) -> &Main {
        match self {
            InferiorRefMut::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_main_mut(&mut self) -> &mut Main {
        match self {
            InferiorRefMut::Main(main) => main,
            _ => panic!("Cannot unwrap Main from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker(&self) -> &Checker {
        match self {
            InferiorRefMut::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn unwrap_checker_mut(&mut self) -> &mut Checker {
        match self {
            InferiorRefMut::Checker(checker) => checker,
            _ => panic!("Cannot unwrap Checker from ProcessIdentity"),
        }
    }

    pub fn process(&self) -> &OwnedProcess {
        match self {
            InferiorRefMut::Main(main) => &main.process,
            InferiorRefMut::Checker(checker) => &checker.process,
        }
    }

    pub fn process_mut(&mut self) -> &mut OwnedProcess {
        match self {
            InferiorRefMut::Main(main) => &mut main.process,
            InferiorRefMut::Checker(checker) => &mut checker.process,
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
}

impl Display for InferiorRefMut<'_> {
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

impl From<&InferiorRefMut<'_>> for InferiorRole {
    fn from(value: &InferiorRefMut) -> Self {
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
