#![allow(clippy::missing_safety_doc)]

use std::arch::asm;
use std::mem;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use ntapi::ntpsapi::{NtSetInformationProcess, PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION};
use once_cell::unsync::Lazy;
use winapi::um::processthreadsapi::GetCurrentProcess;

pub struct SyscallHook {

}

impl SyscallHook {
    pub unsafe fn new() -> anyhow::Result<&'static mut Self> {
        let version = if cfg!(target_pointer_width = "64") { 0 } else { 1 };
        let mut cb = PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
            Reserved: 0,
            Version: version, // x64 -> 0 | x86 -> 1
            Callback: syscall_callback_handler_asm as _
        };

        NtSetInformationProcess(GetCurrentProcess(), 0x28 as _, &mut cb as *mut _ as _, mem::size_of_val(&cb) as _);

        let hook = Self{};

        GLOBAL_SYSCALL_HOOK = Some(hook);

        Ok(GLOBAL_SYSCALL_HOOK.as_mut().unwrap())
    }

    pub unsafe fn unhook(&self) {
        let version = if cfg!(target_pointer_width = "64") { 0 } else { 1 };
        let mut cb = PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
            Reserved: 0,
            Version: version, // x64 -> 0 | x86 -> 1
            Callback: null_mut()
        };

        NtSetInformationProcess(GetCurrentProcess(), 0x28 as _, &mut cb as *mut _ as _, mem::size_of_val(&cb) as _);
    }

    pub(crate) fn handle_syscall(&mut self, return_address: usize, return_value: usize) -> usize {
        println!("syscall!");
        dbg!(return_value);
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

static IN_HANDLER: AtomicBool = AtomicBool::new(false);

#[no_mangle]
unsafe extern "C" fn callback_handler(return_address: usize, return_value: usize, rsp: usize, rbp: usize, rcx: usize, rdx: usize, r8: usize, r9: usize) -> usize {
    if IN_HANDLER.load(Ordering::SeqCst) {
        return return_value;
    }
    IN_HANDLER.store(true, Ordering::SeqCst);

    dbg!(rsp, rbp, rcx, rdx, r8, r9);
    println!("rcx = {:#X}", rcx);
    let stack_ptr = rsp as *const usize;
    dbg!(*stack_ptr.offset(0));
    dbg!(*stack_ptr.offset(1));
    dbg!(*stack_ptr.offset(2));
    dbg!(*stack_ptr.offset(3));
    dbg!(*stack_ptr.offset(4));
    let new_return = GLOBAL_SYSCALL_HOOK.as_mut().unwrap().handle_syscall(return_address, return_value);

    IN_HANDLER.store(false, Ordering::SeqCst);
    new_return
}

#[naked]
unsafe extern "C" fn syscall_callback_handler_asm() {
    asm!("
        mov r8, rsp

        push rbx
        push rbp
        push rdi
        push rsi
        push rsp
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15

        push rcx
        push rdx
        push r8
        push r9

        mov rcx, r10
        mov rdx, rax
        mov r9, rbp
        call callback_handler

        add rsp, 32

        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop rsp
        pop rsi
        pop rdi
        pop rbp
        pop rbx

        jmp r10
    ", options(noreturn))
}

#[cfg(test)]
mod tests {
    use std::mem::size_of_val;
    use std::ptr::{null, null_mut};
    use ntapi::ntmmapi::{MemoryBasicInformation, NtQueryVirtualMemory};
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentProcessId};
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
    use crate::syscall::SyscallHook;

    #[test]
    fn test_handler() {
        unsafe {
            let hook = SyscallHook::new().unwrap();
            let mut region: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

            let a = GetCurrentProcess();
            let b = GetModuleHandleA(null()) as _;
            let c = MemoryBasicInformation;
            let d = &mut region as *mut _ as _;
            let e = size_of_val(&region);
            let f = null_mut();

            dbg!(a as usize, b as usize, c as usize, d as usize, e as usize, f as usize);

            let status = NtQueryVirtualMemory(
                a,
                b,
                c,
                d,
                e,
                f
            );

            dbg!(status);

            println!("asdf: {:p}", NtQueryVirtualMemory as *mut ());
            hook.unhook();
        }
    }
}