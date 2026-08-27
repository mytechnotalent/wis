/* ============================================================================
 * main.c
 * Educational indirect-syscall demo (x64, MinGW-GCC).
 *
 * A controlled demonstration.  It resolves the Syscall Service Number (SSN)
 * and the ntdll `syscall; ret` trampoline address at RUNTIME from the live,
 * loaded ntdll.dll (build-version agnostic), then opens a handle to a
 * process we ourselves just spawned (workspaces.exe, or notepad as fallback)
 * using NtOpenProcess issued two ways:
 *
 *   [DIRECT]   `syscall` executes in OUR module.                  (baseline)
 *   [INDIRECT] we set the SSN + args and JMP into ntdll's
 *              `syscall; ret` so the stack frame chain looks like ntdll.
 *
 * This only obtains a handle to our own child process for viewing PID /
 * basic info -- a benign, functional proof that both mechanisms produce a
 * genuine kernel object handle.
 *
 * Compile (see scripts/build.ps1):
 *   nasm -f win64 syscalls.asm -o syscalls.obj
 *   gcc -O1 -fno-ident -o main.exe main.c syscalls.obj -nostdlib -lkernel32
 * ==========================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

/* Provided by syscalls.asm -- the resolver fills these before each call.
   C (not C++), so plain extern declarations; NASM COFF symbols are C-mangled. */
extern unsigned long       g_ssn;
extern unsigned long long  g_gadget;
extern NTSTATUS SyscallDirect(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                              PCLIENT_ID, ULONG);
extern NTSTATUS SyscallIndirect(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                PCLIENT_ID, ULONG);

/* ---------------------------------------------------------------------------
 * Minimal PE export-table walker over a module's in-memory image.
 * Returns the VA of the named export, or NULL.
 * -------------------------------------------------------------------------*/
static ULONG_PTR ModuleBase;

static void *FindExport(const char *name) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD dirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dirRVA) return NULL;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    /* RVA -> VA mapper */
    PIMAGE_EXPORT_DIRECTORY exp =
        (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + dirRVA);
    if (exp->AddressOfFunctions == 0) return NULL;

    DWORD *names    = (DWORD*)(ModuleBase + exp->AddressOfNames);
    DWORD *funcs    = (DWORD*)(ModuleBase + exp->AddressOfFunctions);
    WORD  *ordinals = (WORD*) (ModuleBase + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *n = (const char*)(ModuleBase + names[i]);
        if (n && _stricmp(n, name) == 0) {
            return (void*)(ModuleBase + funcs[ordinals[i]]);
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * Parse a live Nt* function to recover (SSN, syscall-ret gadget).
 * Works for both clean and patched stubs.
 * -------------------------------------------------------------------------*/
static int ResolveNt(const char *name,
                     unsigned long *outSsn,
                     unsigned long long *outGadget) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { printf("[-] cannot get ntdll handle\n"); return -1; }
    ModuleBase = (ULONG_PTR)ntdll;

    unsigned char *fn = (unsigned char*)FindExport(name);
    if (!fn) { printf("[-] export %s not found\n", name); return -2; }

    /* find  mov r10, rcx  =>  4C 8B D1 */
    int ssn = -1;
    for (unsigned char *p = fn; p < fn + 64; p++) {
        if (p[0]==0x4C && p[1]==0x8B && p[2]==0xD1) {
            for (unsigned char *q = p+3; q < p+40; q++) {
                if (*q==0xB8) { memcpy(&ssn, q+1, 4); break; }   /* mov eax, imm32 */
            }
            break;
        }
    }
    if (ssn < 0) { printf("[-] SSN parse failed for %s\n", name); return -3; }

    /* find `syscall` 0F 05 then trailing `ret` C3.  We jump to the `syscall`
       opcode (the CPU will save the `ret`'s address as its return location,
       so the `ret` brings us back to the original caller). */
    unsigned char *sc = NULL;
    for (unsigned char *p = fn; p < fn + 64; p++)
        if (p[0]==0x0F && p[1]==0x05) { sc = p; break; }
    if (!sc) { printf("[-] no syscall opcode found for %s\n", name); return -4; }

    *outSsn    = (unsigned long)ssn;
    *outGadget = (unsigned long long)(ULONG_PTR)sc;   /* jump target = syscall */
    return 0;
}

/* ---------------------------------------------------------------------------
 * Perform one NtOpenProcess through the given mechanism.
 * -------------------------------------------------------------------------*/
static HANDLE OpenPidFast(DWORD pid, int indirect) {
    CLIENT_ID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid; cid.UniqueThread = NULL;
    OBJECT_ATTRIBUTES oa; memset(&oa, 0, sizeof(oa)); oa.Length = sizeof(oa);
    ACCESS_MASK want = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    HANDLE h = NULL;
    NTSTATUS st;

    if (indirect) st = SyscallIndirect(&h, want, &oa, &cid, 0);
    else          st = SyscallDirect  (&h, want, &oa, &cid, 0);

    printf("      status = 0x%08lx, handle = 0x%p\n", (unsigned long)st, (void*)h);
    return (h && h != INVALID_HANDLE_VALUE) ? h : NULL;
}

int main(void) {
    printf("=== Indirect Syscall PoC (educational) ===\n");
    printf("ntdll base        : 0x%p\n", (void*)GetModuleHandleA("ntdll.dll"));

    /* 1) Resolve SSN + gadget from the LIVE ntdll (build-agnostic). */
    unsigned long ssn = 0;
    unsigned long long gadget = 0;
    if (ResolveNt("NtOpenProcess", &ssn, &gadget) != 0) return 1;
    printf("NtOpenProcess SSN : 0x%lx\n", ssn);
    printf("ntdll gadget      : 0x%llx\n", gadget);
    g_ssn = ssn;
    g_gadget = gadget;

    /* 2) Spawn our benign victim. */
    STARTUPINFOW si; memset(&si,0,sizeof(si)); si.cb=sizeof(si);
    PROCESS_INFORMATION pi; memset(&pi,0,sizeof(pi));
    wchar_t cmd[MAX_PATH];
    wsprintfW(cmd, L"%ws\\workspaces.exe", L"C:\\Windows\\System32");
    if (GetFileAttributesW(cmd) == INVALID_FILE_ATTRIBUTES)
        wsprintfW(cmd, L"notepad.exe");
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        printf("[-] could not spawn victim: %lu\n", GetLastError());
        return 2;
    }
    printf("victim pid        : %lu\n", pi.dwProcessId);

    /* 3) Direct syscall (baseline): syscall executes in our module. */
    printf("\n[DIRECT] NtOpenProcess (syscall in OUR module):\n");
    HANDLE hd = OpenPidFast(pi.dwProcessId, 0);
    if (hd) { CloseHandle(hd); }

    /* 4) Indirect syscall: jump into ntdll's syscall;ret trampoline. */
    printf("[INDIRECT] NtOpenProcess (via ntdll trampoline):\n");
    HANDLE hi = OpenPidFast(pi.dwProcessId, 1);
    if (hi) { CloseHandle(hi); }

    /* 5) Sanity check: the real ntdll API should behave identically. */
    printf("[REF]     ntdll NtOpenProcess:\n");
    HANDLE hr = NULL;
    {
        CLIENT_ID cid; cid.UniqueProcess=(HANDLE)(ULONG_PTR)pi.dwProcessId; cid.UniqueThread=NULL;
        OBJECT_ATTRIBUTES oa; memset(&oa,0,sizeof(oa)); oa.Length=sizeof(oa);
        NTSTATUS st;
        HMODULE nb = GetModuleHandleA("ntdll.dll");
        /* use our FindExport against ntdll to get the real import */
        unsigned char *realNt; ModuleBase=(ULONG_PTR)nb;
        realNt = (unsigned char*)FindExport("NtOpenProcess");
        if (realNt) {
            st = ((NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PCLIENT_ID,ULONG))realNt)
                    (&hr, PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, &oa, &cid, 0);
            printf("      status = 0x%08lx, handle = 0x%p\n", (unsigned long)st, (void*)hr);
        }
        if (hr) CloseHandle(hr);
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    printf("\nDone.\n");
    return 0;
}
