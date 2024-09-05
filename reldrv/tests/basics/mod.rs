use std::arch::asm;

use reldrv::RelShellOptionsBuilder;

use crate::common::{checkpoint_fini, checkpoint_take, trace, trace_w_options};

#[test]
fn basic_checkpointing() {
    trace(|| {
        checkpoint_take();
        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn basic_checkpointing_twice() {
    trace(|| {
        checkpoint_take();
        checkpoint_take();
        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn basic_checkpointing_ten_times_parallel() {
    trace_w_options(
        || {
            for _ in 0..10 {
                checkpoint_take();
            }
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}

#[test]
fn no_checkpoint_fini() {
    trace(|| {
        checkpoint_take();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn duplicated_checkpoint_fini() {
    trace(|| {
        checkpoint_take();
        checkpoint_fini();
        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[cfg(target_arch = "x86_64")]
#[test]
fn register_preservation_after_checkpoint() {
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

        assert_ne!(result, 1);

        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[cfg(target_arch = "aarch64")]
#[test]
fn register_preservation_after_checkpoint() {
    trace(|| {
        unsafe {
            asm!(
                "
                        // X0 is the syscall return value
                        mov x1, 43
                        mov x2, 44
                        mov x3, 45
                        mov x4, 46
                        mov x5, 47
                        mov x6, 48
                        mov x7, 49
                        // X8 is the syscall number
                        mov x9, 51
                        mov x10, 52
                        mov x11, 53
                        mov x12, 54
                        mov x13, 55
                        mov x14, 56
                        mov x15, 57
                        mov x16, 58
                        mov x17, 59
                        mov x18, 60
                        // X19 is used by LLVM
                        mov x20, 62
                        mov x21, 63
                        mov x22, 64
                        mov x23, 65
                        mov x24, 66
                        mov x25, 67
                        mov x26, 68
                        mov x27, 69
                        mov x28, 70
                        // X29 is used by LLVM
                        mov x30, 72

                        mov w8, 0xff77
                        svc #0

                        cmp x1, 43
                        bne 2f
                        cmp x2, 44
                        bne 2f
                        cmp x3, 45
                        bne 2f
                        cmp x4, 46
                        bne 2f
                        cmp x5, 47
                        bne 2f
                        cmp x6, 48
                        bne 2f
                        cmp x7, 49
                        bne 2f
                        cmp x9, 51
                        bne 2f
                        cmp x10, 52
                        bne 2f
                        cmp x11, 53
                        bne 2f
                        cmp x12, 54
                        bne 2f
                        cmp x13, 55
                        bne 2f
                        cmp x14, 56
                        bne 2f
                        cmp x15, 57
                        bne 2f
                        cmp x16, 58
                        bne 2f
                        cmp x17, 59
                        bne 2f
                        cmp x18, 60
                        bne 2f
                        cmp x20, 62
                        bne 2f
                        cmp x21, 63
                        bne 2f
                        cmp x22, 64
                        bne 2f
                        cmp x23, 65
                        bne 2f
                        cmp x24, 66
                        bne 2f
                        cmp x25, 67
                        bne 2f
                        cmp x26, 68
                        bne 2f
                        cmp x27, 69
                        bne 2f
                        cmp x28, 70
                        bne 2f
                        cmp x30, 72
                        bne 2f

                        mov w8, 0xff78
                        svc #0

                        cmp x1, 43
                        bne 3f
                        cmp x2, 44
                        bne 3f
                        cmp x3, 45
                        bne 3f
                        cmp x4, 46
                        bne 3f
                        cmp x5, 47
                        bne 3f
                        cmp x6, 48
                        bne 3f
                        cmp x7, 49
                        bne 3f
                        cmp x9, 51
                        bne 3f
                        cmp x10, 52
                        bne 3f
                        cmp x11, 53
                        bne 3f
                        cmp x12, 54
                        bne 3f
                        cmp x13, 55
                        bne 3f
                        cmp x14, 56
                        bne 3f
                        cmp x15, 57
                        bne 3f
                        cmp x16, 58
                        bne 3f
                        cmp x17, 59
                        bne 3f
                        cmp x18, 60
                        bne 3f
                        cmp x20, 62
                        bne 3f
                        cmp x21, 63
                        bne 3f
                        cmp x22, 64
                        bne 3f
                        cmp x23, 65
                        bne 3f
                        cmp x24, 66
                        bne 3f
                        cmp x25, 67
                        bne 3f
                        cmp x26, 68
                        bne 3f
                        cmp x27, 69
                        bne 3f
                        cmp x28, 70
                        bne 3f
                        cmp x30, 72
                        bne 3f

                        b 4f
                    2:
                        mov x8, 93
                        mov x0, 1
                        svc 0
                    
                    3:
                        mov x8, 93
                        mov x0, 2
                        svc 0
                    4:
                    ",
                out("x0") _,
                out("x1") _,
                out("x2") _,
                out("x3") _,
                out("x4") _,
                out("x5") _,
                out("x6") _,
                out("x7") _,
                out("x8") _,
                out("x9") _,
                out("x10") _,
                out("x11") _,
                out("x12") _,
                out("x13") _,
                out("x14") _,
                out("x15") _,
                out("x16") _,
                out("x17") _,
                out("x18") _,
                out("x20") _,
                out("x21") _,
                out("x22") _,
                out("x23") _,
                out("x24") _,
                out("x25") _,
                out("x26") _,
                out("x27") _,
                out("x28") _,
                out("x30") _,
            )
        };
        0;
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

// #[test]
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
