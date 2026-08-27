<#
.SYNOPSIS
  Build.ps1 - Assembles syscalls.asm and links main.c into main.exe,
  then (optionally) runs the SSN resolver against a copy of ntdll.dll.

.DESCRIPTION
  Requires:
    * NASM  (nasm)    - x64 assembler           (syscalls.asm -> syscalls.obj)
    * MinGW x64 GCC   (gcc) - C compiler + linker

  Usage:
    pwsh -File scripts/build.ps1                       # build only
    pwsh -File scripts/build.ps1 -Ntdll .\ntdll_flare.dll   # also resolve SSN

  Example: copy C:\Windows\System32\ntdll.dll (from the FlareVM) to the repo
  root as ntdll_flare.dll, then run the script with -Ntdll ntdll_flare.dll.
#>

param(
    [string]$Ntdll   = $null
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root "src"
$out  = Join-Path $root "build"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$nasm = "nasm"
$gcc  = "gcc"

Write-Host "== 1/3 Assemble syscalls.asm =="
& $nasm -f win64 -o (Join-Path $out "syscalls.obj") (Join-Path $src "syscalls.asm")
if ($LASTEXITCODE -ne 0) { throw "nasm failed" }

Write-Host "== 2/3 Compile + link main.exe =="
# Link against the standard MinGW runtime plus kernel32/ntdll (for the
# console CRT like printf we let the default runtime handle it).
& $gcc -O1 -fno-ident -s -o (Join-Path $out "main.exe") `
       (Join-Path $src "main.c") (Join-Path $out "syscalls.obj") `
       -lkernel32 -lntdll
if ($LASTEXITCODE -ne 0) { throw "gcc failed" }

Write-Host ""
Write-Host "Build OK -> $(Join-Path $out 'main.exe')"

if ($Ntdll) {
    Write-Host ""
    Write-Host "== 3/3 Resolve SSN from $Ntdll =="
    & pwsh -File (Join-Path $PSScriptRoot "Resolve-SSN.ps1") -Path $Ntdll
}
