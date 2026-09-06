param([string]$AssemblyPath)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if ([IntPtr]::Size -ne 8) { throw 'Run this test in 64-bit PowerShell.' }
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('wand-launcher-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($scratch) | Out-Null

# Source-only mode verifies the native launcher without WPF/NuGet build dependencies.
if ($AssemblyPath) {
    $assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path $AssemblyPath).Path)
} else {
    $support = Join-Path $scratch 'Support.cs'
    @'
namespace AsarSharp.Utils {
    public static class Extensions {
        public static int ReadFull(this System.IO.Stream stream, byte[] buffer, int offset, int count) {
            int total = 0;
            while (total < count) {
                int read = stream.Read(buffer, offset + total, count - total);
                if (read <= 0) break;
                total += read;
            }
            return total;
        }
    }
}
'@ | Set-Content -LiteralPath $support
    $sources = @('WandEnhancer/Core/FuseLauncher.cs', 'WandEnhancer/Core/ElectronFuse.cs',
        'WandEnhancer/Core/ProcessInfo.cs', 'WandEnhancer/View/MainWindow/Logs.cs') |
        ForEach-Object { Join-Path $repoRoot $_ }
    $types = Add-Type -Path ($sources + $support) -PassThru
    $assembly = $types[0].Assembly
}
$launcher = $assembly.GetType('WandEnhancer.Core.FuseLauncher', $true)
$launch = $launcher.GetMethod('Launch')
$eventType = $launcher.GetNestedType('DEBUG_EVENT', [Reflection.BindingFlags]'NonPublic')
if ([Runtime.InteropServices.Marshal]::SizeOf([type]$eventType) -ne 176) { throw 'Wrong x64 DEBUG_EVENT layout' }
$processInfo = $assembly.GetType('WandEnhancer.Core.ProcessInfo', $true)
$queryArgs = [object[]]@([IntPtr]::Zero, $null)
$null = $processInfo.GetMethod('GetImageBase').Invoke($null, $queryArgs)
if ($queryArgs[1] -notmatch 'NTSTATUS 0x[0-9A-F]{8}') { throw 'Missing native failure diagnostics' }

$fuse = $assembly.GetType('WandEnhancer.Core.ElectronFuse', $true)
$memory = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
try {
    $data = [Text.Encoding]::ASCII.GetBytes('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX') + [byte[]]@(1, 8) + [Text.Encoding]::ASCII.GetBytes('11111111')
    [Runtime.InteropServices.Marshal]::Copy($data, 0, $memory, $data.Length)
    $clearArgs = [object[]]@([Diagnostics.Process]::GetCurrentProcess().Handle, $memory, [long]38, $null)
    if (-not $fuse.GetMethod('ClearAt').Invoke($null, $clearArgs)) { throw "Explicit image base failed: $($clearArgs[3])" }
    if ([Runtime.InteropServices.Marshal]::ReadByte($memory, 38) -ne 114) { throw 'Fuse was not written' }
    # A mismatched image must remain untouched, even with a plausible RVA.
    [Runtime.InteropServices.Marshal]::WriteByte($memory, 0, 0)
    [Runtime.InteropServices.Marshal]::WriteByte($memory, 38, 49)
    if ($fuse.GetMethod('ClearAt').Invoke($null, $clearArgs)) { throw 'Mismatched image accepted' }
    if ([Runtime.InteropServices.Marshal]::ReadByte($memory, 38) -ne 49) { throw 'Mismatched image modified' }
} finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($memory)
}
Write-Host 'PASS: explicit image-base write, sentinel guard and native error diagnostics.'

$compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$wire = Join-Path $scratch 'fuse.bin'
[IO.File]::WriteAllBytes($wire, [Text.Encoding]::ASCII.GetBytes('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX') + [byte[]]@(1, 8) + [Text.Encoding]::ASCII.GetBytes('11111111'))
$fixture = Join-Path $scratch 'WandFixture.exe'
$foreign = Join-Path $scratch 'ForeignFixture.exe'
& $compiler /nologo /target:exe /platform:x64 "/out:$fixture" "/resource:$wire" (Join-Path $PSScriptRoot 'tests/launcher-fixture.cs')
if ($LASTEXITCODE -ne 0) { throw 'Fixture compilation failed' }
Copy-Item -LiteralPath $fixture -Destination $foreign
$hashBefore = (Get-FileHash -LiteralPath $fixture).Hash
$logType = $assembly.GetType('WandEnhancer.View.MainWindow.ELogType', $true)
$loggerType = [Action``2].MakeGenericType([string], $logType)
$logger = { param($message, $level) Write-Host "[$level] $message" } -as $loggerType

$output = Join-Path $scratch 'result.txt'
$result = $launch.Invoke($null, [object[]]@([string]$fixture, [string]"parent `"$output`" `"$foreign`"", $logger))
if (-not $result) { throw 'Launcher rejected a healthy fixture' }
if ((Get-Content -Raw $output) -notmatch 'child verified') { throw 'Late child was not patched before execution' }
if ((Get-Content -Raw "$output.foreign") -ne 'detached') { throw 'Foreign child executed under debugger' }
if ((Get-FileHash -LiteralPath $fixture).Hash -ne $hashBefore) { throw 'Launcher changed the executable on disk' }
Write-Host 'PASS: main and late child patched before execution; foreign child detached; executable unchanged.'

$clock = [Diagnostics.Stopwatch]::StartNew()
$result = $launch.Invoke($null, [object[]]@([string]$fixture, [string]"failure `"$output`"", $logger))
if ($result -or $clock.Elapsed.TotalSeconds -gt 20) { throw 'Child integrity failure was not surfaced promptly' }
Write-Host 'PASS: child failure returns false without waiting for parent exit.'

# Intentionally retain tiny fixtures/logs for inspection if native debugging fails.
Write-Host "Launcher fixtures: $scratch"
