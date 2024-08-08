use strum::FromRepr;

#[derive(FromRepr, Debug, PartialEq, Eq, Clone, Copy)]
#[repr(usize)]
pub enum TestCustomSysno {
    TestPmc = 0xffaa,
    MigrateChecker,
    TakeExecPoint,
}
