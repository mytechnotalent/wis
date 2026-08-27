<img src="https://github.com/mytechnotalent/is/blob/main/wis.png?raw=true">

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/Reverse-Engineering-Tutorial)

<br>

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

# Windows Indirect Syscall

A minimal, runnable, educational demonstration of **direct** vs **indirect**
Windows system calls in NASM x64 assembly, driven by a C wrapper, targeting a
copy of the FlareVM's `ntdll.dll` so the Syscall Service Number (SSN) is
resolved at runtime rather than hardcoded per build.

**Read `TUTORIAL.md` for the full walkthrough.** This README is just the quick
start.

## What it does

Opens a handle to a process (workspaces.exe, or notepad as fallback) using
`NtOpenProcess` three ways and shows they behave identically:

- `[DIRECT]` — `syscall` executes in our module.
- `[INDIRECT]` — we set the SSN + args, then `jmp` into ntdll's `syscall` opcode
  so the stack frame chain looks like a normal ntdll → kernel call.
- `[REF]` — the real ntdll API, as a value check.

## Layout

```
src/syscalls.asm      NASM x64 stubs + globals (g_ssn, g_gadget)
src/main.c            runtime PE export resolver + 3-way demo
scripts/build.ps1     nasm + gcc link
scripts/Resolve-SSN.ps1  parse a ntdll file -> SSNs + syscall gadgets
```

## Build & run

Requires **NASM** and **MinGW-w64 GCC** on PATH.

```powershell
# bring the FlareVM ntdll into the repo
Copy-Item C:\Windows\System32\ntdll.dll .\ntdll_flare.dll

# build + resolve SSN
pwsh -File scripts/build.ps1 -Ntdll .\ntdll_flare.dll

# run
.\build\main.exe
```

Expected output (SSN/handles will vary by build):

```
NtOpenProcess SSN : 0x26
[DIRECT]   NtOpenProcess ... status = 0x00000000, handle = 0x..348
[INDIRECT] NtOpenProcess ... status = 0x00000000, handle = 0x..348
[REF]      ntdll NtOpenProcess ... status = 0x00000000, handle = 0x..348
```

## Notes

This is a **lab/teaching** artifact for Windows internals and userland-hooking
education. Run it on your own FlareVM against your own spawned process. For
legal-use context: syscalls are an OS primitive; understanding them is standard
RE/red-team curriculum and equally useful for defenders writing tooling.

<br>

## License
[MIT](https://github.com/mytechnotalent/wis/blob/main/LICENSE)
