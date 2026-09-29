# Copyright 2026 Summon Software Labs
# SPDX-License-Identifier: Apache-2.0
#
# Packaging and downstream-consumption proof.
#
#   1. configure and build Release and Debug from the working tree
#   2. install Release through CMake install/export into a clean prefix
#   3. build an INDEPENDENT out-of-tree project against that prefix with
#      find_package, and run it, so the INSTALLED artifact is what is exercised
#   4. produce the CPack archive and list it
#
# No step uses a timeout. A step that hangs is a defect, not something to wait out.

[CmdletBinding()]
param(
    [string] $BuildRoot = "build",
    [string] $Prefix = "artifacts/install"
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\msvc_env.ps1"
Import-MsvcEnvironment

$root = (Get-Location).Path
$prefixPath = Join-Path $root $Prefix

Write-Output "== configure Release =="
Invoke-Native cmake -S . -B "$BuildRoot/release" -G Ninja -DCMAKE_BUILD_TYPE=Release -DDF_BUILD_TESTS=OFF
Write-Output "== build Release =="
Invoke-Native cmake --build "$BuildRoot/release"

Write-Output "== configure Debug =="
Invoke-Native cmake -S . -B "$BuildRoot/debug" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DDF_BUILD_TESTS=OFF
Write-Output "== build Debug =="
Invoke-Native cmake --build "$BuildRoot/debug"

if (Test-Path $prefixPath) { Remove-Item -Recurse -Force $prefixPath }

Write-Output "== install Release into $Prefix =="
Invoke-Native cmake --install "$BuildRoot/release" --prefix $prefixPath

Write-Output "== installed layout =="
Get-ChildItem -Recurse -File $prefixPath |
    ForEach-Object { $_.FullName.Substring($prefixPath.Length + 1) } |
    Sort-Object |
    Write-Output

Write-Output "== build and run the out-of-tree consumer against the installed package =="
$consumerBuild = Join-Path $root "$BuildRoot/consumer"
if (Test-Path $consumerBuild) { Remove-Item -Recurse -Force $consumerBuild }
Invoke-Native cmake -S scripts/consumer -B $consumerBuild -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$prefixPath"
Invoke-Native cmake --build $consumerBuild
$consumerExe = Join-Path $consumerBuild "consumer.exe"
& $consumerExe
if ($LASTEXITCODE -ne 0) { throw "the installed-artifact consumer exited $LASTEXITCODE" }

Write-Output "== CPack archive =="
Invoke-Native cmake --build "$BuildRoot/release" --target package
Get-ChildItem "$BuildRoot/release" -Filter "DecommissioningFabric-*.zip" -Recurse |
    ForEach-Object { Write-Output "package: $($_.Name) ($($_.Length) bytes)" }

Write-Output "PACKAGE CHECK PASSED: the installed artifact was exercised by an independent consumer"
