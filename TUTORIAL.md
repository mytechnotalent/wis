***
**LEGAL DISCLAIMER:**
The information, tools, and code provided in this repository and course are strictly for educational, research, and defensive purposes only. 

You are explicitly prohibited from using any materials contained herein to access, test, modify, or exploit any device, network, or system that you do not own 100% or for which you do not have explicit, documented, and legally binding authorization to interact with.

By using this repository and course, you acknowledge and agree that:

1. Any illegal, unauthorized, or malicious use of this information is solely your responsibility.
2. The author(s) and contributor(s) of this repository and course shall not be held liable for any damages, legal repercussions, criminal charges, or unauthorized actions resulting from the use, misuse, or abuse of the contents herein.
3. You will comply with all applicable local, state, national, and international laws regarding cybersecurity and computer fraud.

**IF YOU DO NOT AGREE WITH THESE TERMS, DO NOT USE THIS REPOSITORY AND COURSE.**

***

<br>

# Indirect Syscalls on Windows x64
## An Educational Book Chapter

*— The Syscall Service Number (SSN), the full x64 register map, userland
EDR hooking, and how a direct vs indirect syscall really works, explained
step by step and verified in a lab.*

This chapter is written as a self-contained instructional unit. It assumes you
have a passing familiarity with what a CPU, a stack, and a memory address are,
but it does **not** assume you know anything about Windows internals, ntdll,
or the `syscall` instruction. I build every concept from the ground up before
we ever look at a single line of assembly beyond simple instructions.

A running, verified example accompanies this chapter — a tiny NASM x64 PoC that
opens a process handle three ways (direct syscall, indirect syscall, and the
normal Windows API) so you can see the mechanism with your own eyes on your own
FlareVM. The example code is minimal and *does not* perform injection or any
other malicious activity; it only obtains a handle to a benign process that
you, the operator, spawned yourself. Keep this work inside your lab.

---

## Table of Contents

1. What an EDR does (and why it can see your syscalls)
2. The journey from an application call to the kernel
3. The full x64 register map, one register at a time
4. The stack and the calling convention (who saves what, where)
5. Anatomy of a real `ntdll` syscall stub (hex level)
6. What "hooking" actually does to those bytes
7. Direct syscall: skip the hook entirely
8. Indirect syscall: finish inside ntdll
9. Where the EDR looks, and what each path looks like to it
10. Step-by-step trace of the PoC
11. Practical lab: getting the SSN from your FlareVM
12. Going further (a map of the surrounding research)

---

## 1. What an EDR does (and why it can see your syscalls)

An **Endpoint Detection and Response (EDR)** product is software that runs on
an endpoint (a workstation or a server) and watches what that machine does, so
that malicious activity can be detected. The abbreviation matters more than the
name: it is the successor to classic antivirus (AV), which mostly scanned files
on disk for known "signatures" (byte patterns) of known malware.

An EDR goes far beyond file scanning. A good modern EDR hooks four layers:

1. **Kernel** — it loads a kernel driver that registers callbacks. So even if
   user-mode never calls a hooked function, the EDR *still* sees the system
   call land in the kernel and can inspect the arguments there.
2. **User-mode DLL injection** — it injects its own DLL into every process and
   hooks (rewrites the prologue of) sensitive `ntdll.dll` / `kernel32.dll`
   functions, so that it can inspect arguments *before* they reach the kernel.
3. **ETW (Event Tracing for Windows)** — Microsoft's built-in tracing is
   enabled so the EDR receives telemetry (process creation, thread starts,
   image loads, syscall events) even for events user-mode hooks might miss.
4. **Call-stack / behavioral heuristics** — it inspects *not just what was
   called, but how it was reached*: the return addresses, the module ownership
   of frames, unusual call patterns, and so on.

For this chapter the **user-mode DLL hook (layer 2)** is the important one,
and we will return to it constantly.

### Why the EDR wants to see your syscalls

Consider what malware must do to run on a Windows box. It needs a way to:

- Allocate executable memory,
- Write its payload into that memory,
- Alter page protections,
- Create or take over a thread to run the payload,
- Open handles to other processes, read/write their memory.

Every one of those steps bottoms out in a `Nt*` system call: `NtAllocateVirtualMemory`,
`NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`,
`NtOpenProcess`, `NtReadVirtualMemory`, and friends. A defensive product that
can see the *arguments* of those calls (what address, what size, what
protections, which process) has an enormous amount of signal about whether the
actor is doing something malicious.

This is the key idea: **normal, benign programs reach the kernel through the
documented ntdll functions, and an EDR is positioned right there, at the
ntdll boundary, to inspect them.** If you can reach the kernel in a way that
skips that inspection point, the EDR's user-mode layer is blind to your call.

That is precisely the motivation for the technique at the center of this
chapter: relocating the `syscall` instruction so it executes somewhere the EDR
does not control. But before we can appreciate the trick, you need to know what
the untricked path looks like, byte by byte.

---

## 2. The journey from an application call to the kernel

Imagine a program that wants to open another process to read its memory. It
calls `OpenProcess()`, which is exported by `kernel32.dll`. But `kernel32.dll`
does not talk to the kernel on its own. It is a "wrapper" library; its only job
is to validate and repackage arguments and then forward the work to the real
system-call layer.

The actual hierarchy on 64-bit Windows is:

```
your_app.exe
    │
    ▼  (call OpenProcess / WriteProcessMemory / ...)
kernel32.dll        ← "public" Win32 API, argument checking, Unicode helpers
    │
    ▼  (call NtOpenProcess / NtWriteVirtualMemory / ...)
ntdll.dll           ← the actual system-call stubs, <syscall> lives here
    │
    ▼  (syscall / int 2Eh)
kernel (ntoskrnl)   ← ring 0: does the real work, returns a status
```

`ntdll.dll` is the bottom of user mode. It is the only DLL that the kernel
"trusts" to issue system calls; it contains one small stub for each system
service. These stubs are tiny — on the order of a dozen bytes — because they
do almost nothing: they load the service number into a register, move the first
argument to the right register, and execute the privileged `syscall`
instruction that transfers control to the kernel.

`syscall` (opcode `0F 05`) is an AMD64 instruction that switches the CPU from
user mode (ring 3) to kernel mode (ring 0) and jumps to a kernel entry point,
passing the service number in `eax`. The kernel then looks up the service
number in a table (`KiServiceTable`) to find the right function to call — the
same way a `switch` statement dispatches to a case.

### Why this layering matters for us

Because `ntdll.dll` is the *single* choke point through which every system
call must pass in user mode, it is also the *single* best place for an EDR to
intercept them. The EDR's injected DLL only has to change a handful of bytes at
the start of a few dozen `Nt*` stubs, and suddenly it can inspect every system
call made by every process on the machine. That tiny footprint is the target we
are studying.

---

## 3. The full x64 register map, one register at a time

This whole technique hangs on exactly how the CPU and the calling convention
use registers. So let's be rigorous. On the x86-64 (AMD64) architecture, the
CPU has **16 general-purpose 64-bit registers**, plus a few special ones.
Here is every one of them that matters.

### 3.1 The general-purpose registers

| 64-bit | 32-bit | 16-bit | 8-bit | Role at a glance |
|--------|--------|--------|-------|------------------|
| `rax`  | `eax`  | `ax`   | `al`  | accumulator, **return value**, and **syscall number** |
| `rbx`  | `ebx`  | `bx`   | `bl`  | general (callee-saved on Windows) |
| `rcx`  | `ecx`  | `cx`   | `cl`  | **1st integer/pointer arg**; **clobbered by `syscall` (return addr)** |
| `rdx`  | `edx`  | `dx`   | `dl`  | **2nd arg** |
| `rsi`  | `esi`  | `si`   | `sil` | general |
| `rdi`  | `edi`  | `di`   | `dil` | general |
| `rbp`  | `ebp`  | `bp`   | `bpl` | frame pointer (callee-saved) |
| `rsp`  | `esp`  | `sp`   | `spl` | **stack pointer** (always the top of the stack) |
| `r8`   | `r8d`  | `r8w`  | `r8b` | **3rd arg** |
| `r9`   | `r9d`  | `r9w`  | `r9b` | **4th arg** |
| `r10`  | `r10d` | `r10w` | `r10b`| **the "first arg" parking lot for syscalls** |
| `r11`  | `r11d` | `r11w` | `r11b`| scratch; **clobbered by `syscall` (holds flags)** |
| `r12`  | `r12d` | `r12w` | `r12b`| callee-saved |
| `r13`  | `r13d` | `r13w` | `r13b`| callee-saved |
| `r14`  | `r14d` | `r14w` | `r14b`| callee-saved |
| `r15`  | `r15d` | `r15w` | `r15b`| callee-saved |

The 8- and 16-bit views let you touch a sub-region of a register. `eax` is the
low 32 bits of `rax`. Writing to `eax` **zeroes** the upper 32 bits of `rax`.
Writing to `al` leaves the rest of `rax` alone. This detail matters a lot for the
SSN: we load the service number into `eax`, and the kernel reads `eax`.

### 3.2 The special-purpose registers

| Register | Purpose |
|----------|---------|
| `rip`   | **Instruction pointer** — the address of the next instruction to execute. You normally cannot read/write it directly in user mode. |
| `rflags` | **Flags register** — carries the CPU condition/status bits (`ZF`, `CF`, `SF`, `OF`, …) that branches like `jne` test. |
| `cs`, `ds`, `es`, `ss`, `gs`, `fs` | Segment registers. On 64-bit Windows most are basically flat/unused, but `gs` points at the **Thread Environment Block (TEB)**, which we touch conceptually below. `fs` is the Process Environment Block (PEB) pointer base on x64 via `gs`. |

### 3.3 The three registers that make or break a syscall

Of all sixteen, exactly **three** are special for the `syscall` instruction, and
the whole "indirect syscall" technique is really about these three:

1. **`eax`** — must contain the **Syscall Service Number (SSN)** when
   `syscall` executes. The kernel uses it to dispatch.
2. **`rcx`** — the CPU **automatically saves the return address into `rcx`**
   when `syscall` executes. That means whatever was in `rcx` (your *first
   argument*, per the normal calling convention) is **destroyed**. So the OS
   calling convention adds a rule: **before `syscall`, you must move your
   first argument out of `rcx` into `r10`** to keep it alive.
3. **`r11`** — the CPU **automatically saves the flags into `r11`**, destroying
   anything that was there. Like `rcx`, it is a scratch casualty of `syscall`.

The other argument registers (`rdx`, `r8`, `r9`) and the on-stack arguments are
*not* touched by `syscall`, which is why they can pass straight through.

> **The single most important rule in this chapter:** when a program issues a
> syscall, the *first* argument must be in **`r10`**, not `rcx`, and the service
> number must be in **`eax`**. Everything else can stay where the ordinary
> calling convention put it.

---

## 4. The stack and the calling convention (who saves what, where)

### 4.1 What the stack is

The stack is a region of memory that grows *downward* in memory addresses. The
`rsp` register points at the current top. `call` pushes a return address and
moves `rsp`; `ret` pops it and jumps back. `push`/`pop` move `rsp` by 8 bytes
at a time on x64.

### 4.2 The Microsoft x64 calling convention

When you call a function in C/C++ compiled for 64-bit Windows, the *caller*
follows this contract:

1. Integer/pointer arguments 1–4 go in **`rcx`, `rdx`, `r8`, `r9`** (left to
   right).
2. Arguments 5 and beyond go **on the stack**, pushed right-to-left, each
   consuming 8 bytes.
3. The caller **always reserves 32 bytes of "shadow space"** immediately above
   the return address (four 8-byte slots at `[rsp+0x08]`..`[rsp+0x28]`, or from
   the callee's view `[rsp+0x20]` onward) — even for functions with fewer than
   four parameters. The callee is allowed to use that space to spill `rcx`,
   `rdx`, `r8`, `r9`.
4. `rsp` must be **16-byte aligned** at the point of a `call` (specifically, at
   the callee's entry, `rsp % 16 == 8`, because the `call` already pushed 8
   bytes for the return address).
5. Return value goes in **`rax`**.
6. **Caller-saved (volatile):** `rax`, `rcx`, `rdx`, `r8`–`r11` — the caller
   must assume these are destroyed by the call.
7. **Callee-saved (non-volatile):** `rbx`, `rbp`, `rsi`, `rdi`, `r12`–`r15`
   — a callee that uses them must preserve them (push + pop or save to shadow
   space) before returning.

Point 6 is why our stub's use of `r10` and `r11` is "free": both are volatile,
so we may trash them without restoring anything. Point 5 means `rax` carries
the `NTSTATUS` back to the caller.

### 4.3 Where the fifth argument physically sits

For a 5-argument function such as `NtOpenProcess`, the layout as seen *inside*
the callee is:

```
[rsp+0x18]  arg5
[rsp+0x10]  arg4 (shadow slot)
[rsp+0x08]  arg3 (shadow slot)
[rsp+0x00]  arg2 (shadow slot)   <- return address is BELOW this point
```

Wait, let me be careful and give the canonical picture. At the moment the `ret`
from the *caller's* `call` happens, the callee looks at:

| offset (from callee's `rsp` on entry) | contents |
|---------------------------------------|----------|
| `[rsp+0x20]` | arg5 (the first stack argument) |
| `[rsp+0x18]` | shadow slot 4 (unused slot) |
| `[rsp+0x10]` | shadow slot 3 |
| `[rsp+0x08]` | shadow slot 2 |
| `[rsp+0x00]` | shadow slot 1 |
| *(below)*    | the **return address** that `call` pushed |

So **arg5 is at `[rsp+0x20]`** from the callee's entry `rsp`. And because the
`Nt*` syscall stub uses *the very same calling convention*, arg5 is sitting at
exactly the place ntdll's own stub expects it. Our indirect stub therefore does
**not** need to touch the stack at all for a 5-argument syscall. Beautiful — but
you should understand *why*, which is this layout.

---

## 5. Anatomy of a real `ntdll` syscall stub (hex level)

Now that the registers and stack are sorted, let's read an actual stub. This is
the real `NtOpenProcess` from the ntdll used in this lab, shown byte by byte:

```
offset  bytes                     instruction
------  ------------------------  ----------------------------------------
+0x00   4C 8B D1                  mov  r10, rcx          ; park arg1 into R10
+0x03   B8 26 00 00 00            mov  eax, 0x26         ; SSN = 0x26 (38)
+0x08   F6 04 25 08 03 FE 7F 01   test byte [0x1FFE0308], 1  ; KdDebuggerEnabled
+0x10   75 03                     jne  +0x12             ; skip syscall if debugger
+0x12   0F 05                     syscall                ; <-- the transition
+0x14   C3                        ret
```

Decode it line by line:

- **`4C 8B D1` = `mov r10, rcx`.** Copies the first argument (which arrived in
  `rcx`) into `r10`, because `syscall` is about to destroy `rcx`. This is the
  mandatory ABI shuffle we keep talking about.
- **`B8 26 00 00 00` = `mov eax, 0x26`.** Loads the **Syscall Service Number**.
  The `B8` is the opcode for `mov eax, imm32`, so the SSN is literally the four
  bytes that follow: `26 00 00 00` → `0x00000026`.
- **`F6 04 25 …` = `test byte [0x1FFE0308], 1`**, then **`75 03` = `jne +0x12`**.
  This checks a kernel variable that tells the stub "is a debugger attached?"
  Under a normal debugger-free run the byte is 0, the `test` is not taken, and
  the branch falls through to the `syscall`.
- **`0F 05` = `syscall`.** Yes — the opcode for `syscall` is literally the two
  bytes `0F 05`. The CPU switches to ring 0 and dispatches according to `eax`.
- **`C3` = `ret`.** The kernel mode of a syscall returns to the *next* user
  instruction after `syscall`, which is this `ret`. This `ret` pops the return
  address that was pushed when someone called `NtOpenProcess`.

Two things to memorize from this one function:

1. The **SSN is the `imm32` following the `B8`**. `0x26` → dispatching table
   entry 38 → `NtOpenProcess`.
2. The **`syscall` opcode (`0F 05`) is a fixed offset away from the function
   entry** (here `+0x12`), and it is followed by a `ret` (`C3`).

Number 2 is the *entire* payload of the indirect-syscall technique.

---

## 6. What "hooking" actually does to those bytes

"Userland hooking" sounds abstract, but it is just a memory write. The EDR's
injected DLL overwrites the first several bytes of an `Nt*` stub with a jump to
the EDR's own function. There are a few flavors; here are the two you will see.

### 6.1 The classic E9 (5-byte) near jump hook

The stub's first `5` bytes are replaced:

```
BEFORE:
+0x00  4C 8B D1                 mov r10, rcx
+0x03   B8 26 00 00 00          mov eax, 0x26
...

AFTER  (hooked):
+0x00  E9 xx xx xx xx           jmp rel32   ->  EDR!NtOpenProcess_hook
+0x05  B8 26 00 00 00           (original bytes shifted/stored)
```

Now the very first byte of `ntdll!NtOpenProcess` is a `jmp` to the EDR. The EDR
reads the arguments (still in `rcx, rdx, r8, r9`, `[rsp+0x20]`), makes its
detection decisions, and — if it allows the call — jumps back into the
*original* ntdll code (which it stashed somewhere) to let the syscall proceed.

### 6.2 The detour / hotpatch hook

x64 uses the `FF 25` indirect-jump form because it can target any 64-bit
address:

```
+0x00  FF 25 00 00 00 00        jmp  qword ptr [rip+0]
+0x06  xx xx xx xx xx xx        <absolute address of the hook>
```

### 6.3 What the hook can and cannot see

Because the hook sits at the *entry*, it sees:

- The **entire argument list** (the process handle to open, the access rights,
  the memory address, the buffer, the sizes, the protections).
- The **return address** of the caller that invoked ntdll.

And crucially, it sees that the call *happened at all* — and can log it.

What it **does not necessarily** change is the `syscall` byte at `+0x12`.
Hooking the tail is wasteful and risky, so the EDR leaves the rest of the stub
mostly intact. That tail — the `0F 05 C3` — is our way out.

> **Interlude — the concept of "not seeing it".** If a call to `NtOpenProcess`
> is routed such that the *entry bytes that the EDR patched are never
> executed*, the EDR's user-mode interceptor never runs. The syscall still
> reaches the kernel, but this particular inspection point is bypassed. That is
> the goal of both techniques in the next two sections; they differ only in
> *where* `syscall` executes.

---

## 7. Direct syscall: skip the hook entirely

The **direct syscall** is the "brute force" answer. Write your own tiny stub
that does not call ntdll's function at all:

```asm
; our module's .text
SyscallDirect:
    mov  r10, rcx            ; park arg1, per the ABI
    mov  eax, dword [g_ssn]  ; put the SSN in eax
    syscall                  ; <-- executes HERE, in OUR module
    ret
```

Because we jump *straight* to the CPU instruction and never invoke
`ntdll!NtOpenProcess`, the EDR's hook at the entry of that function is never
executed. The kernel receives `eax = SSN`, `r10 = arg1`, `rdx/r8/r9/[rsp+0x20] =
the rest`, and opens the handle. The user-mode hook is blind to it.

That is the whole trick, and it is elegant. But it buys a benefit and sells a
cost:

**Benefit:** simple; only needs the SSN.

**Cost (why direct syscalls get caught):**
1. **You must know the SSN**, and the SSN is **different on every Windows
   build**. A hardcoded table is a fingerprint and breaks across versions, so
   you have to resolve it at runtime (more below).
2. The `syscall` executes in **your** module. When the kernel returns, control
   returns *into your `.text`*. An EDR that inspects **return addresses** or
   does a **stack walk** sees a frame belonging to `main.exe` (or, worse, an
   anonymous/protected region) right under the kernel boundary — and that is a
   well-known tell of a direct syscall. Benign software never has its own
   syscall stub, so its presence is suspicious by itself.

Detections such as `callstack_spoofing` / `unbacked_module` often flag exactly
this: a syscall whose surrounding code does not come from `ntdll`.

---

## 8. Indirect syscall: finish inside ntdll

The **indirect syscall** keeps the benefit (the hook never runs) and removes the
biggest cost (the return address is no longer in *our* module).

The idea: don't execute `syscall` in your own code, and don't call the *hooked
entry* of ntdll. Instead — *jump into the middle of ntdll*, to the `0F 05`
byte, so the actual transition happens inside ntdll where it "belongs".

```asm
; our module's .text
SyscallIndirect:
    mov  r10, rcx            ; park arg1
    mov  eax, dword [g_ssn]  ; SSN
    mov  r11, qword [g_gadget]  ; = address of ntdll's 0F 05
    jmp  r11                 ; land on ntdll's `syscall` opcode
```

Trace what happens from the `jmp`:

1. `jmp r11` moves the instruction pointer to the `0F 05` byte *inside ntdll*.
2. The CPU executes `syscall` with `eax=SSN`, `r10=arg1`, etc. — exactly as if
   ntdll had done it.
3. The CPU saves the **address of the next ntdll instruction** (the `C3` `ret`)
   into `rcx` as the kernel's return address.
4. The kernel does its thing and returns to that `C3`.
5. That `C3` `ret` pops the return address that *our caller* pushed when it
   called `SyscallIndirect` (us), and jumps back to that caller.

So the *visible* call chain, as seen by an unwinder looking at return addresses,
is:

```
the caller of SyscallIndirect
        │  (called →)
        ▼
   <return address that points into main.exe>   <- our caller
        │  (jumped →)
        ▼
   ntdll!...+0x12 (the syscall) ... ntdll!...+0x14 (the ret)
        │
        ▼
   kernel
```

Crucially, **the frame immediately below the kernel boundary is ntdll, not our
module.** A return-address / stack inspection of the syscall sees ntdll code and
thinks everything is normal. That is the entire point of *indirect*.

### Why it still "reads" like real ntdll (stack-frame nuance)

A sophisticated EDR not only checks the return address of the syscall but also
walks the *whole* stack using the exception-handling (`.pdata`) metadata of
each module. When it unwinds past the `ret` at `+0x14`, it lands on... our
caller's return address, which points into `main.exe`. So an indirect syscall is
*not* invisible to a rigorous stack walk — the frames above the syscall still
belong to our module. What it *is* good at defeating is the *cheaper* checks:
"was this syscall's immediate return address inside ntdll?" If the EDR only
checks one or two frames, the indirect syscall passes.

This is the crucial, honest nuance: **indirect syscalls raise the bar but do
not make you invisible.** Every successive detection counter-measure (spoofing
*full* stacks, using `trampoline` gadgets far from ntdll entry, `int 2e`,
rotating SSNs, etc.) is a response to an EDR that started walking deeper. The
lab we built is the clean *baseline* indirect syscall so you can see the
mechanism, not a claim that it beats a specific product.

### Direct vs indirect, side by side

| | Direct | Indirect |
|---|---|---|
| Where `syscall` executes | **our module** | **ntdll** (via `jmp`) |
| SSN source | hardcoded or resolved | resolved at runtime |
| Bytes to be written | 1 stub in our module | 1 stub + 1 saved address |
| Return address of syscall | our `.text` | ntdll `+0x14` |
| Near-frame looks like | custom code | ntdll |
| Full stack walk | clearly ours | ours above ntdll (still unwinds to us) |
| EDR layer defeated | user-mode hook | user-mode hook + return-addr check |

---

## 9. Where the EDR looks, and what each path looks like to it

Let's tie the technique back to the four EDR layers from Section 1, and say
explicitly what a direct syscall and an indirect syscall each "look like" to
that layer.

| EDR layer | What it does | Direct syscall | Indirect syscall |
|---|---|---|---|
| **User-mode hook** (injected DLL, `ntdll` entry) | sees the call + args | **bypassed** (entry skipped) | **bypassed** (entry skipped) |
| **Kernel driver callback** | sees every syscall + args | still sees it | still sees it |
| **ETW telemetry** | sees syscall events | still sees it | still sees it |
| **Return-address / shallow stack** | is the call's context ntdll-like? | **caught** (ours) | **passes** (ntdll at the boundary) |
| **Deep stack walk** (`.pdata` unwind) | where do frames above really live? | **caught** (ours) | **catchable** (unwinds to our module) |
| **SSN-table / version fingerprint** | are the SSNs hardcoded? | **caught** if hardcoded | **reduced** (resolved at runtime) |

**The honest bottom line, in one paragraph:** direct and indirect syscalls both
defeat the user-mode *hook* (so the EDR's injected inspection code never runs
on your call). Direct syscalls are additionally flagged by anything that looks
at *where* control goes after the syscall, because it lands in your module.
Indirect syscalls push that return address into ntdll, defeating shallow checks
and raising the bar for deep walks. But the **kernel driver and ETW still see
the syscall itself**, and a determined deep stack walk can still unwind to your
code. Neither technique makes you invisible to a well-instrumented EDR; both are
cat-and-mouse *improvements*, not cloaks. Any material that tells you otherwise
is overselling.

---

## 10. Step-by-step trace of the PoC

The accompanying code (`src/syscalls.asm` + `src/main.c`) performs the
resolution and the three-way comparison. Let's walk its actual execution.

### Step 1 — Resolve the SSN and gadget at runtime

`main.c` calls `GetModuleHandleA("ntdll.dll")` to get the base address, then
walks the PE **export table** to find `NtOpenProcess`. It reads the prologue:

```c
// pseudo-code of ResolveNt()
fn       = FindExport("NtOpenProcess");      // VA of the stub
find "4C 8B D1" (mov r10,rcx) then "B8"      // -> SSN = imm32 after B8
find first "0F 05"                            // -> the syscall opcode = gadget
g_ssn    = ssn;                              // e.g. 0x26
g_gadget = fn + <offset of 0F 05>;           // e.g. fn + 0x12
```

Why at runtime? Because the SSN **changes between Windows builds**. `0x26`
happens to be right on this build, but a different build may put `NtOpenProcess`
at a different slot. By reading the immediate from the live stub, the same
binary works across windows updates. The PowerShell `Resolve-SSN.ps1` does the
same parse against a *file copy* so you can inspect the FlareVM's ntdll *before*
running anything.

### Step 2 — Spawn a benign victim

`main.c` spawns `workspaces.exe` (falling back to `notepad.exe`) in a suspended
state, purely so we have a real PID to open a handle to. Nothing more.

### Step 3 — Direct syscall

Arguments are set per the normal convention (5 args: handle ptr, access mask,
object attributes, client id, info class). `SyscallDirect` does:
`mov r10,rcx` → `mov eax,[g_ssn]` → `syscall` (in our module) → `ret`. The
handle comes back in memory at `*handlePtr`, status in `rax`.

### Step 4 — Indirect syscall

Same arguments. `SyscallIndirect` does:
`mov r10,rcx` → `mov eax,[g_ssn]` → `mov r11,[g_gadget]` → `jmp r11`. The
syscall runs inside ntdll; the kernel returns to ntdll's `ret`; it pops back to
us with a valid handle.

### Step 5 — Reference call

`main.c` also calls the *real* ntdll `NtOpenProcess` as a control. If all three
return `STATUS_SUCCESS` and the same handle value, all three genuinely reached
the kernel and opened the same handle. Any mismatch tells you your stub or
gadget is wrong.

### Step 6 — Interpret the output

```
[DIRECT]   status = 0x00000000, handle = 0x..34C
[INDIRECT] status = 0x00000000, handle = 0x..34C
[REF]      status = 0x00000000, handle = 0x..34C
```

All `0x00000000` = `STATUS_SUCCESS`. Same handle → same real object. That is
your proof that the indirect mechanism is a *genuine* syscall, not a trick that
merely looks like one.

---

## 11. Practical lab: getting the SSN from your FlareVM

This is the "get the SSN for the hook" workflow you asked about. You want to
know, for a given `Nt*` function on *your* FlareVM's build, what SSN it uses
and where its `syscall` gadget is. Two ways:

### A. Pull the live value (in-process, at runtime)

`main.exe` already does this. Run it on the FlareVM and read the `NtOpenProcess
SSN: 0x26` line. For *other* functions, change the string passed to
`ResolveNt()` in `src/main.c` and rebuild.

### B. Inspect a copy of the ntdll file (off-process)

Copy ntdll off the FlareVM, then run the parser:

```powershell
Copy-Item C:\Windows\System32\ntdll.dll .\ntdll_flare.dll
pwsh -File scripts/Resolve-SSN.ps1 -Path .\ntdll_flare.dll
```

Output:

```
==== Target: NtOpenProcess ====
  SSN                  : 0x26 (38)
  Function RVA         : 0x160830
  'syscall' RVA        : 0x160842
  'ret' RVA            : 0x160844
  Gadget offset from fn start: 0x12 bytes
```

It also prints a table of **every** `Nt*` stub with its SSN and gadget — so if
you're building a chain (e.g. `NtAllocateVirtualMemory` → `NtWriteVirtualMemory`
→ `NtProtectVirtualMemory` → `NtCreateThreadEx`), you can pull all their SSNs at
once and confirm their gadget offsets.

> **Lab tip.** Because the values are *resolved at runtime*, you don't strictly
> need to know the SSN ahead of time — the process parses it off the live
> module. Use the parser when you want to *see* the numbers, understand a
> hook, or when analyzing a static sample that hardcoded them.

---

## 12. Going further — a map of the surrounding research

The baseline you now understand unlocks reading the wider literature. Key
milestones, each a natural next topic:

- **Hell's Gate / Halo's Gate** — finding the SSN / a *fresh* (unhooked) ntdll
  copy when the in-memory one has been patched (e.g. the `B8` or `syscall` bytes
  are replaced by a `jmp`). The answer becomes: read a *different* copy of
  ntdll (a cached instance or one on disk) and use its immediate.
- **SysWhispers / SysWhispers2 / FreshyCalls** — code generators that emit
  per-syscall stubs (both direct and indirect flavors), saving the "resolve the
  SSN" bookkeeping.
- **Randomized / trampoline gadgets** — instead of jumping to ntdll's canonical
  `+0x12`, find a `syscall; ret` *elsewhere* in a trusted module to defeat
  gadgets that look for the well-known offset.
- **Full stack spoofing** — because a *deep* unwind still lands in your module,
  some tooling fabricates a fake, benign stack so the entire backtrace reads
  like a normal call.
- **`int 2Eh`, vsyscall filtering, CVaB (Control-flow-enforcing syscall)** —
  alternate transition paths and the CPU/OS features that try to control which
  bytes a `syscall` may originate from.
- **The defensive angle** — knowing these tells (unbacked syscall stubs,
  return addresses outside ntdll, gadget-offset fingerprints, deep-unwind
  mismatches) is exactly how you *tune* an EDR to catch them. Studying the
  bypass is, for the defender, studying what a detection must look for.

### Closing note

You now possess a precise mental model: the three registers that govern a
syscall (`eax`, `rcx→r10`, and the flags), the SSN as an `imm32` after `B8`, the
`0F 05` opcode, the layout of the stack for a 5-argument call, and the exact
three-instruction difference between a direct and an indirect syscall. You also
know, honestly, which EDR layers each defeats and which it does not. That is the
foundation — the rest is variations on the same theme, and you can now read any
of the public research with full comprehension.

Keep it in the lab.
