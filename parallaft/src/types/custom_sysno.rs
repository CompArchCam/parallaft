use strum::FromRepr;

#[derive(FromRepr, Debug, PartialEq, Eq, Clone, Copy)]
#[repr(usize)]
pub enum CustomSysno {
    CheckpointTake = 0xff77,
    CheckpointFini,
    CheckpointSync,

    LegacyRtSetCliControlAddr = 0xff7a,
    RelRtLibSetCounterAddr = 0xff7b,
    DumpExecPoint = 0xff7c,
    AssertInProtection = 0xff7d,
    SlicingStart = 0xff7e,
    CheckExecPointSync = 0xff7f,
}
