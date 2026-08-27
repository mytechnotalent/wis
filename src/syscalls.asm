; ============================================================================
;  syscalls.asm
;  Indirect syscall stubs for AMD64 Windows (NASM)
; ----------------------------------------------------------------------------
;  Educational PoC, x64.
;
;  Two equivalent calling paths for the SAME underlying system call are shown
;  side by side.  Each stub has an EXPLICIT 5-argument signature that mirrors
;  the NT API (e.g. NtOpenProcess) so the demonstration is real and returns
;  an actual kernel handle.  The only difference is WHERE `syscall` executes:
;
;    * SyscallDirect   : `syscall` runs in OUR module.   Return address of the
;                        kernel lands in our .text.
;    * SyscallIndirect : 3 instructions set up the ABI, then we JMP to ntdll's
;                        `syscall; ret` pair so the kernel return address and
;                        the frame above it belong to ntdll (stealthier).
;
;  AMD64 syscall essentials (the whole reason for the mov r10,rcx dance):
;    - The CPU saves the *return address* in RCX and RFLAGS in R11, so user
;      code must move the first argument out of RCX into R10 before `syscall`.
;    - 2nd..4th args stay in RDX,R8,R9; 5th+ on the stack at [rsp+20h].
;    - The SSN goes in EAX.
;
;  g_ssn and g_gadget are filled in at runtime by the C resolver (main.c),
;  which parses the live ntdll export table -> build-version agnostic.
; ============================================================================

BITS 64
DEFAULT REL

global g_ssn
global g_gadget

section .data
align 8
g_ssn:    dd 0        ; DWORD syscall service number
align 8
g_gadget: dq 0        ; QWORD address of ntdll's `syscall; ret` pair

section .text

; ----------------------------------------------------------------------------
; extern "C" NTSTATUS SyscallDirect(
;     PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID, ULONG);
;   First arg -> RCX, so we copy RCX->R10 and issue `syscall` from our module.
; ----------------------------------------------------------------------------
global SyscallDirect
SyscallDirect:
    mov     r10, rcx            ; syscall ABI: 1st arg must live in R10
    mov     eax, dword [rel g_ssn]
    syscall
    ret

; ----------------------------------------------------------------------------
; extern "C" NTSTATUS SyscallIndirect(
;     PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID, ULONG);
;   Same setup, but JMP to ntdll's `syscall; ret` gadget.  The `ret` then
;   returns to OUR caller, so the recorded return address / frame chain reads
;   as if control flowed straight from ntdll into the kernel.
; ----------------------------------------------------------------------------
global SyscallIndirect
SyscallIndirect:
    mov     r10, rcx
    mov     eax, dword [rel g_ssn]
    mov     r11, qword [rel g_gadget]
    jmp     r11
    ; never returns here.
