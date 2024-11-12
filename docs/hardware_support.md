# Hardware support

To enable execution point record and replay, Parallaft requires access to accurate branch-counting hardware performance counters, which are processor hardware-dependent. The following table lists status of supported processors.

## Status table

| Architecture | Processor                                         | Supported? | Tested? | Notes                                                            |
| ------------ | ------------------------------------------------- | ---------- | ------- | ---------------------------------------------------------------- |
| aarch64      | Apple M2 (non-Pro/Max/Ultra)                      | Y          | Y       |                                                                  |
| aarch64      | Other pre-M4 Apple Silicon                        | Y          | N       |                                                                  |
| aarch64      | Arm Neoverse N1                                   | Y          | Y       |                                                                  |
| aarch64      | Arm Neoverse V2                                   | Y          | Y       |                                                                  |
| aarch64      | Arm Cortex A76 with ARMv8-PMUv3                   | Y          | Y       |                                                                  |
| x86_64       | Intel Core i7-12700                               | Y          | Y       | Known issues with `memcpy`/`memchr`/`memrchr` functions in glibc |
| x86_64       | Intel Core i7-14700                               | Y          | Y       | Ditto                                                            |
| x86_64       | Other Intel Alder Lake and Raptor Lake processors | Y          | N       |                                                                  |

## Developing support for a new processor

Parallaft requires access to an accurate and deterministic branch-counting hardware performance counter that count branch instructions executed in userspace. On an Apple M2, this is simply the counter that counts `INST_BRANCH` event (see [this commit](https://github.com/CompArchCam/parallaft/commit/a5dc32e5cea9c53c4e72aecfff40a9c4488e89fc)).  However, some processors like Intel Alder Lake overcount the number of branches executed by number of return from interrupts/exceptions from a higher privilege level to the userspace. To compensate this, a combination of branch counters are used. Specifically, Parallaft substrates the far branch count (which include the ret-from-irq-exc number above) from the all branch count (see [this](https://github.com/CompArchCam/parallaft/blob/ea1bc46c07ce7ce1e169f327c3bc22c8d29452ce/parallaft/src/types/perf_counter/symbolic_events/branch.rs#L58)).

To add support for a new processor, you need to refer to your processor manual to find out the event ID of the branch counter. Then you add your processor model and the event ID to Parallaft source. You can refer to [this](https://github.com/CompArchCam/parallaft/commit/a5dc32e5cea9c53c4e72aecfff40a9c4488e89fc) and [this](https://github.com/CompArchCam/parallaft/commit/fa9319fa604433d435a949e0a5d808f67f3c669f) commit for reference.
