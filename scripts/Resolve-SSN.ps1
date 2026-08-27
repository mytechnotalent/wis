<#
.SYNOPSIS
  Resolve-SSN.ps1 - Parses a 64-bit ntdll.dll file and reports, for every
  Nt* system-call stub, the Syscall Service Number (SSN), the offset of the
  'syscall' instruction, and the offset of the 'syscall; ret' trampoline.

.DESCRIPTION
  The native x64 API in ntdll.dll is a thin set of stubs, each shaped like:

      mov  r10, rcx            ; 4C 8B D1
      mov  eax, <SSN>          ; B8 imm32      <-- the SSBERT: SSN is imm32
      test dword [g_KdDebuggerEnabled], 0   ; optional (debug builds)
      syscall                  ; 0F 05         <-- the transition
      ret                      ; C3

  Reading the bytes of the export gives us the SSN without needing to know
  the Windows build (10.0.xxxxx) in advance.  We ALSO locate the byte offset
  of `syscall; ret` so main.c can JMP to that gadget for an *indirect* syscall.

  This script is for use against a COPY of ntdll from the FlareVM (e.g.
  C:\Windows\System32\ntdll.dll copied to the lab), or against the local one
  for comparison.  It only READS the file.

.EXAMPLE
  # Copy ntdll from the FlareVM into the project, then:
  pwsh -File scripts/Resolve-SSN.ps1 -Path .\ntdll_x64.dll
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$ExportName = "NtOpenProcess"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "File not found: $Path"
}

$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))

function Read-U32([int]$off) {
    return [BitConverter]::ToUInt32($bytes, $off)
}
function Read-U64([int]$off) {
    return [BitConverter]::ToUInt64($bytes, $off)
}
function Read-U16([int]$off) {
    return [BitConverter]::ToUInt16($bytes, $off)
}

# --- Validate PE header -----------------------------------------------------
if ((Read-U16 0) -ne 0x5A4D) { throw "Not a PE file (bad MZ)." }
$peOff = [int](Read-U32 0x3C)
if ($bytes[$peOff] -ne 0x50 -or $bytes[$peOff+1] -ne 0x45) { throw "Bad PE signature." }
$machine = (Read-U16 ($peOff + 4))
if ($machine -ne 0x8664) { throw "Expected a x64 (AMD64) PE, got machine 0x{0:X}." -f $machine }

$optOff   = $peOff + 24
$magic    = Read-U16 $optOff
if ($magic -ne 0x20B) { throw "Expected PE32+ optional header." }

# Number of data directories (for PE32+ it's usually 16).
$numSections   = Read-U16 ($peOff + 6)
$sizeOptHdr    = Read-U16 ($peOff + 20)

# --- Locate the Export Directory (index 0) ---------------------------------
$ddOffset = $optOff + 112       # PE32+: 112 bytes into optional header
$expRVA   = Read-U32 ($ddOffset + 0)
$expSize  = Read-U32 ($ddOffset + 4)
if ($expRVA -eq 0) { throw "No export directory." }

# --- Section headers: map RVA <-> file offset ------------------------------
$sectionTable = $optOff + $sizeOptHdr
$sections = @()
for ($i = 0; $i -lt $numSections; $i++) {
    $sOff = $sectionTable + ($i * 40)
    $sections += [pscustomobject]@{
        RVA  = [int](Read-U32 ($sOff + 12))
        VSize= [int](Read-U32 ($sOff + 8))
        Raw  = [int](Read-U32 ($sOff + 20))
    }
}
function RvaToFile([int]$rva) {
    foreach ($s in $sections) {
        if ($rva -ge $s.RVA -and $rva -lt ($s.RVA + $s.VSize)) {
            return $s.Raw + ($rva - $s.RVA)
        }
    }
    throw "RVA 0x{0:X} not in any section." -f $rva
}

# --- Parse export directory ------------------------------------------------
$expFile  = RvaToFile $expRVA
$numNames = Read-U32 ($expFile + 24)
# The AddressOf* members hold image RVAs (relative to image base), so we
# translate them directly - do NOT add $expRVA.
$addrOfFuncs    = RvaToFile ([int](Read-U32 ($expFile + 28)))
$addrOfNames    = RvaToFile ([int](Read-U32 ($expFile + 32)))
$addrOfOrdinals = RvaToFile ([int](Read-U32 ($expFile + 36)))

# --- Build name -> RVA map -------------------------------------------------
$byName = @{}
for ($i = 0; $i -lt $numNames; $i++) {
    $nameRVA   = [int](Read-U32 ($addrOfNames + $i*4))
    $ordIdx    = [int](Read-U16 ($addrOfOrdinals + $i*2))
    $funcRVA   = [int](Read-U32 ($addrOfFuncs + $ordIdx*4))

    $nameFile = RvaToFile $nameRVA
    $sb = New-Object System.Text.StringBuilder
    $j = $nameFile
    while ($bytes[$j] -ne 0) { [void]$sb.Append([char]$bytes[$j]); $j++ }
    $name = $sb.ToString()
    if ($name -like "Nt*") {
        $byName[$name] = @{ FuncRVA = $funcRVA; Ordinal = $ordIdx }
    }
}

Write-Host "Exported Nt* functions found: $($byName.Count)"

# --- Identify the syscall opcode bytes for the requested export ------------
function Get-SyscallInfo([string]$name) {
    if (-not $byName.ContainsKey($name)) {
        return $null
    }
    $file = RvaToFile $byName[$name].FuncRVA

    # Scan for the classic x64 syscall stub prologue:
    #   4C 8B D1        mov r10, rcx
    #   B8 <imm32>      mov eax, imm32   <- SSN is bytes at offset +4 .. +7
    #   0F 05           syscall
    #   C3              ret
    $ssn = $null
    for ($k = $file; $k -lt ($file + 64); $k++) {
        if ($bytes[$k] -eq 0x4C -and $bytes[$k+1] -eq 0x8B -and $bytes[$k+2] -eq 0xD1) {
            # mov r10, rcx found; expect mov eax,imm32 next (maybe a 'test'
            # instruction or 'jmp' in between on patched/system builds)
            $ssn = -1
            for ($m = $k + 3; $m -lt ($k + 32); $m++) {
                if ($bytes[$m] -eq 0xB8) {
                    $ssn = [int](Read-U32 ($m + 1))
                    break
                }
            }
            break
        }
    }
    if ($null -eq $ssn) { return $null }

    # Find the 'syscall' (0F 05) and the trailing 'ret' (C3).
    $syscallOff = -1
    for ($k = $file; $k -lt ($file + 64); $k++) {
        if ($bytes[$k] -eq 0x0F -and $bytes[$k+1] -eq 0x05) { $syscallOff = $k; break }
    }
    $retOff = -1
    for ($k = $syscallOff + 1; $k -lt ($file + 64); $k++) {
        if ($bytes[$k] -eq 0xC3) { $retOff = $k; break }
    }

    $funcRVA = $byName[$name].FuncRVA
    return [pscustomobject]@{
        Name        = $name
        FuncRVA     = $funcRVA
        SSN         = $ssn
        SyscallFileOff = $syscallOff
        SyscallRVA  = ($funcRVA + ($syscallOff - $file))
        RetFileOff  = $retOff
        RetRVA      = ($funcRVA + ($retOff - $file))
        # Gadget = the `syscall` opcode RVA.  We jump THERE; the CPU saves the
        # following `ret`'s address as the kernel return target.
        GadgetRVA   = ($funcRVA + ($syscallOff - $file))
    }
}

# --- Report the single requested export + all of them ----------------------
$target = Get-SyscallInfo $ExportName
if ($null -eq $target) {
    Write-Warning "Could not parse stub for '$ExportName' (not exported or prologue not matched)."
} else {
    Write-Host ""
    Write-Host ("==== Target: {0} ====" -f $target.Name)
    Write-Host ("  SSN                  : 0x{0:X} ({0})" -f $target.SSN)
    Write-Host ("  Function RVA         : 0x{0:X}" -f $target.FuncRVA)
    Write-Host ("  'syscall' RVA        : 0x{0:X}" -f $target.SyscallRVA)
    Write-Host ("  'ret' RVA            : 0x{0:X}" -f $target.RetRVA)
    Write-Host ""
    Write-Host ("  Gadget (syscall) RVA : 0x{0:X}" -f $target.GadgetRVA)
    $gadgetOffsetByte = $target.GadgetRVA - $target.FuncRVA
    Write-Host ("  Gadget offset from fn start: 0x{0:X} bytes" -f $gadgetOffsetByte)
    Write-Host "  Use these when launching main.exe on the target build."
}

Write-Host ""
Write-Host "==== All parsed Nt* stubs (first 60) ===="
$rows = @($byName.Keys | Sort-Object | ForEach-Object {
    Get-SyscallInfo $_
}) | Where-Object { $null -ne $_ -and $_.SyscallFileOff -ge 0 }
$rows | Select-Object -First 60 |
    Format-Table Name, SSN, FuncRVA, SyscallRVA, RetRVA -AutoSize
Write-Host "Total stubs parsed successfully: $($rows.Count)"
