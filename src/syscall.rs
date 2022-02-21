#![allow(clippy::missing_safety_doc)]

use std::arch::asm;
use std::mem;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use ntapi::ntpsapi::{NtSetInformationProcess, PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION};
use once_cell::unsync::Lazy;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{CONTEXT, RtlRestoreContext};

pub struct SyscallHook {}

impl SyscallHook {
    pub unsafe fn new() -> anyhow::Result<&'static mut Self> {
        let version = if cfg!(target_pointer_width = "64") { 0 } else { 1 };
        let mut cb = PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
            Reserved: 0,
            Version: version, // x64 -> 0 | x86 -> 1
            Callback: syscall_callback_handler_asm as _,
        };

        NtSetInformationProcess(GetCurrentProcess(), 0x28 as _, &mut cb as *mut _ as _, mem::size_of_val(&cb) as _);

        let hook = Self {};

        GLOBAL_SYSCALL_HOOK = Some(hook);

        Ok(GLOBAL_SYSCALL_HOOK.as_mut().unwrap())
    }

    pub unsafe fn unhook(&self) {
        let version = if cfg!(target_pointer_width = "64") { 0 } else { 1 };
        let mut cb = PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
            Reserved: 0,
            Version: version, // x64 -> 0 | x86 -> 1
            Callback: null_mut(),
        };

        NtSetInformationProcess(GetCurrentProcess(), 0x28 as _, &mut cb as *mut _ as _, mem::size_of_val(&cb) as _);
    }

    pub(crate) fn handle_syscall(&mut self, return_address: usize, return_value: usize, ctx: &Context) -> usize {
        println!("syscall!");
        dbg!(return_value);
        dbg!(ctx);
        println!("return = {:#X}", return_address);

        5
    }
}

impl Drop for SyscallHook {
    fn drop(&mut self) {
        unsafe { self.unhook(); }
    }
}

static mut GLOBAL_SYSCALL_HOOK: Option<SyscallHook> = None;

#[thread_local]
static IN_HANDLER: AtomicBool = AtomicBool::new(false);

#[no_mangle]
unsafe extern "C" fn callback_handler(ctx: *mut Context) -> usize {
    let ctx = ctx.as_mut().unwrap();

    if IN_HANDLER.load(Ordering::SeqCst) {
        return ctx.rax;
    }
    IN_HANDLER.store(true, Ordering::SeqCst);

    // 24 is where arg stack starts
    // let rsp = ctx.rsp as *mut usize;
    // for i in -100..100 {
    //     println!("Stack {}: {:#X}", i, *rsp.offset(i))
    // }
    let new_return = GLOBAL_SYSCALL_HOOK.as_mut().unwrap().handle_syscall(ctx.r10, ctx.rax, ctx);

    IN_HANDLER.store(false, Ordering::SeqCst);

    new_return
}

#[repr(C)]
#[derive(Debug)]
pub struct Context {
    // 0x0
    pub rcx: usize,
    // 0x8
    pub rdx: usize,
    // 0x10
    pub r8: usize,
    // 0x18
    pub r9: usize,
    // 0x20
    pub rsp: *mut usize,
    // 0x28
    pub rax: usize,
    // 0x30
    pub r10: usize,
}

#[naked]
unsafe extern "C" fn syscall_callback_handler_asm() {
    /*
     Upon call:
     - R10 is the return address, Rip should be set to there after handling hook
     - Rax is the return value
     - We need to return with all other general purpose regs the same to prevent fucking up whoever called it

     What we need to save and pass to handler:
     - Rcx  |
     - Rdx  |
     - R8   |
     - R9   - ( First four args)
     - Rsp  ( Args on stack )
     - Rax  ( Return value )
     */
    asm!(
    "push rsp", // Save all registers used
    "push rbx",
    "push rcx",
    "push rdx",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "push rdi",
    "push rsi",
    "push rbp",
    "",
    "mov r15, rsp",             // Save rsp before modifying and aligning the stack
    "",
    "sub rsp, {context_size}",  // Store Context on stack
    "and rsp, -10h",            // Align stack
    "mov [rsp], rcx",           // Store registers using Context struct
    "mov [rsp+8h], rdx",
    "mov [rsp+10h], r8",
    "mov [rsp+18h], r9",
    "mov [rsp+20h], rsp",
    "mov [rsp+28h], rax",
    "mov [rsp+30h], r10",
    "mov rcx, rsp",             // Move stack pointer to rcx (param for callback handler)
    "",
    "sub rsp, 20h",             // Shadow stack space
    "call callback_handler",    // Call the handler
    "",
    "mov rsp, r15",             // Restore stack pointer
    "pop rbp",                  // Restore registers
    "pop rsi",
    "pop rdi",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rsp",
    "",
    "jmp r10",                  // Go back to code
    context_size = const std::mem::size_of::<Context>(),
    options(noreturn))
}

#[cfg(test)]
mod tests {
    use std::mem::size_of_val;
    use std::ptr::{null, null_mut};
    use ntapi::ntmmapi::{MemoryBasicInformation, NtQueryVirtualMemory};
    use ntapi::ntseapi::NtAccessCheckByType;
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId};
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
    use crate::syscall::SyscallHook;

    #[test]
    fn test_handler() {
        unsafe {
            let hook = SyscallHook::new().unwrap();
            let mut region: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            // let a = GetCurrentProcess();
            // let b = GetModuleHandleA(null()) as _;
            // let c = MemoryBasicInformation;
            // let d = &mut region as *mut _ as _;
            // let e = size_of_val(&region);
            // let f = null_mut();
            let a: usize = 0xABABABAB;
            let b: usize = 0xBCBCBCBC;
            let c: usize = 0xCDCDCDCD;
            let d: usize = 0xDEDEDEDE;
            let e: usize = 0xEFEFEFEF;
            let f: usize = 0xFAFAFAFA;

            dbg!(a as usize, b as usize, c as usize, d as usize, e as usize, f as usize);

            let status = NtQueryVirtualMemory(
                a as _,
                b as _,
                c as _,
                d as _,
                e as _,
                f as _,
            );

            dbg!(status);

            println!("asdf: {:p}", NtQueryVirtualMemory as *mut ());
            hook.unhook();
        }
    }
}