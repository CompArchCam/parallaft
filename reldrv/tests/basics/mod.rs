use std::arch::asm;

use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};

use serial_test::serial;

#[test]
#[serial] // we don't allow a single tracer to trace multiple processes
fn basic_checkpointing() {
    setup();

    assert_eq!(
        trace(|| {
            checkpoint_take();
            checkpoint_fini();
            0
        }),
        0
    )
}

#[test]
#[serial]
fn no_checkpoint_fini() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            0
        }),
        0
    );
}

#[test]
#[serial]
fn duplicated_checkpoint_fini() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            checkpoint_fini();
            checkpoint_fini();
            0
        }),
        0
    );
}

#[test]
#[serial]
fn register_preservation_after_checkpoint() {
    setup();
    assert_eq!(
        trace(|| {
            let result: u64;

            unsafe {
                asm!(
                    "
                            mov rdi, 12345
                            push rbx
                            push rdx
                            push rsi
                            push rdi
                            push r8
                            push r9
                            push r10
                            push r12
                            push r13
                            push r14
                            push r15
                            pushfq

                            mov rax, 0xff77
                            syscall

                            pushfq
                            pop rax
                            pop r11
                            cmp rax, r11
                            jne 1f

                            pop rax
                            cmp rax, r15
                            jne 1f

                            pop rax
                            cmp rax, r14
                            jne 1f

                            pop rax
                            cmp rax, r13
                            jne 1f

                            pop rax
                            cmp rax, r12
                            jne 1f

                            pop rax
                            cmp rax, r10
                            jne 1f

                            pop rax
                            cmp rax, r9
                            jne 1f

                            pop rax
                            cmp rax, r8
                            jne 1f

                            pop rax
                            cmp rax, rdi
                            jne 1f

                            pop rax
                            cmp rax, rsi
                            jne 1f

                            pop rax
                            cmp rax, rdx
                            jne 1f

                            pop rax
                            cmp rax, rbx
                            jne 1f

                            mov rax, 0
                            jmp 2f
                            1:
                            mov rax, 1
                            2:
                            ",
                    out("rcx") _,
                    out("r11") _,
                    out("rdi") _,
                    lateout("rax") result,
                )
            }

            if result == 1 {
                return 1;
            }

            0
        }),
        0
    )
}

// #[test]
// #[serial]
// #[should_panic]
// fn oom_handling() {
//     setup();
//     assert_eq!(
//         trace(|| {
//             let size: usize = (procfs::Meminfo::new().unwrap().mem_free as f64 * 0.75) as _; // 75% free mem
//             println!("size = {}", size);
//             let addr = unsafe {
//                 mman::mmap::<OwnedFd>(
//                     None,
//                     NonZeroUsize::new_unchecked(size),
//                     mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
//                     mman::MapFlags::MAP_PRIVATE | mman::MapFlags::MAP_ANONYMOUS,
//                     None,
//                     0,
//                 )
//                 .map_err(|_| std::process::exit(0))
//                 .unwrap()
//             };

//             let buf = unsafe { slice::from_raw_parts_mut(addr as *mut u8, size) };

//             checkpoint_take();

//             for c in buf.chunks_mut(4096) {
//                 c[0] = 42;
//             }

//             checkpoint_fini();
//             checkpoint_sync();

//             0
//         }),
//         0
//     )
// }
