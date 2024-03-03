use std::arch::asm;

use crate::common::{checkpoint_fini, checkpoint_take, trace};

#[test]
fn basic_checkpointing() {
    trace(|| {
        checkpoint_take();
        checkpoint_fini();
        Ok::<_, ()>(())
    })
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
    .expect()
}

#[test]
fn no_checkpoint_fini() {
    trace(|| {
        checkpoint_take();
        Ok::<_, ()>(())
    })
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
    .expect()
}

#[cfg(target_arch = "aarch64")]
#[test]
fn register_preservation_after_checkpoint() {
    trace(|| {
        unsafe {
            asm!(
                "
                        mov x0, 42
                        mov x1, 43
                        mov x2, 44
                        mov x3, 45
                        mov x4, 46
                        mov x5, 47
                        mov x6, 48
                        mov x7, 49
                        mov x9, 51
                        mov x10, 52

                        mov w8, 0xff77
                        svc #0

                        mov x1, x7
                        
                        mov x8, 49
                        cmp x8, x7
                        bne 1f

                        mov w8, 0xff78
                        svc #0

                        mov x8, 49
                        cmp x8, x7
                        bne 2f

                        b 3f
                    1:
                        mov x8, 93
                        mov x0, 1
                        svc 0
                    
                    2:
                        mov x8, 93
                        mov x0, 2
                        svc 0
                    3:
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
            )
        };
        0;
        Ok::<_, ()>(())
    })
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
