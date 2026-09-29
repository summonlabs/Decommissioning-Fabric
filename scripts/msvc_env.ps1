# Copyright 2026 Summon Software Labs
# SPDX-License-Identifier: Apache-2.0
#
# Shared helper: import the MSVC toolchain environment into the CURRENT
# PowerShell process and invoke native commands with correct argument quoting.
#
# The workspace path contains spaces, so nothing here builds a command string
# that a shell has to re-split. Native commands are invoked through PowerShell's
# argument array, which passes each argument as one argv element whatever it
# contains.

function Import-MsvcEnvironment {
    [CmdletBinding()]
    param([string] $VcVars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat")

    if (-not (Test-Path $VcVars)) { throw "vcvars not found at $VcVars" }
    $capture = '"' + $VcVars + '" >nul 2>&1 && set'
    $lines = & cmd.exe /c $capture
    if ($LASTEXITCODE -ne 0) { throw "vcvars failed with $LASTEXITCODE" }
    foreach ($line in $lines) {
        if ($line -match '^([^=]+)=(.*)$') {
            Set-Item -Path ("env:" + $matches[1]) -Value $matches[2] -ErrorAction SilentlyContinue
        }
    }
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        throw "cl.exe is still not on PATH after importing the MSVC environment"
    }
}

function Invoke-Native {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string] $Program,
        [Parameter(ValueFromRemainingArguments = $true)][string[]] $Arguments
    )
    & $Program @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "$Program $($Arguments -join ' ') failed with exit code $code"
    }
    return $code
}
