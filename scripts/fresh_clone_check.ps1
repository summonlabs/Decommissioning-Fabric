# Copyright 2026 Summon Software Labs
# SPDX-License-Identifier: Apache-2.0
#
# Fresh-clone closure check.
#
# Clones the repository into a clean directory and builds, tests, installs, and
# consumes it there. This proves the committed tree is self-contained: nothing a
# build needs is left behind in the working copy, uncommitted, or gitignored.
#
# No step uses a timeout.

[CmdletBinding()]
param(
    [string] $Source = "",
    [string] $WorkDir = ""
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\msvc_env.ps1"

if ([string]::IsNullOrEmpty($Source)) { $Source = (Get-Location).Path }
if ([string]::IsNullOrEmpty($WorkDir)) {
    $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dfab_fresh_clone_" + [System.Guid]::NewGuid().ToString("N"))
}

Write-Output "fresh clone of $Source into $WorkDir"
git clone --quiet --no-hardlinks "$Source" "$WorkDir"
if ($LASTEXITCODE -ne 0) { throw "git clone failed" }

Import-MsvcEnvironment

Push-Location $WorkDir
try {
    Write-Output "== files in the clone =="
    Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notmatch "\\\.git\\" } |
        ForEach-Object { $_.FullName.Substring($WorkDir.Length + 1) } | Sort-Object | Write-Output

    Write-Output "== configure =="
    Invoke-Native cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DDF_BUILD_TESTS=ON -DDF_BUILD_BENCHMARKS=ON
    Write-Output "== build =="
    Invoke-Native cmake --build build
    Write-Output "== ctest =="
    Invoke-Native ctest --test-dir build --output-on-failure
    Write-Output "== install =="
    Invoke-Native cmake --install build --prefix (Join-Path $WorkDir "install")
    Write-Output "== consumer against the installed package =="
    $consumer = Join-Path $WorkDir "build\consumer"
    Invoke-Native cmake -S scripts/consumer -B $consumer -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$(Join-Path $WorkDir 'install')"
    Invoke-Native cmake --build $consumer
    $consumerExe = Join-Path $consumer "consumer.exe"
    & $consumerExe
    if ($LASTEXITCODE -ne 0) { throw "the installed-artifact consumer exited $LASTEXITCODE" }

    Write-Output "FRESH CLONE CHECK PASSED"
}
finally {
    Pop-Location
    Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
}
