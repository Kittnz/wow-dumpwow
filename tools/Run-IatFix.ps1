# Orchestrate dumpwow -> (optional WOWDump) -> Scylla IAT fix
$ErrorActionPreference = "Stop"
$classic = "C:\Program Files (x86)\World of Warcraft\_classic_"
$cata = "C:\Program Files (x86)\World of Warcraft\_classic_cata"
$x64dbg = Join-Path $cata "xdbg64\xdbg64\x64\x64dbg.exe"
$scyllaDir = Join-Path $cata "xdbg64\xdbg64\x64"
$fixer = Join-Path $cata "wow-dumpwow\tools\ScyllaIatFix.exe"
$dumpwow = Join-Path $classic "dumpwow.exe"

# Prefer binaries from classic folder (our built ones)
if (-not (Test-Path $dumpwow)) { $dumpwow = Join-Path $cata "dumpwow.exe" }

$ready = Join-Path $classic "dumpwow_ready.txt"
$done = Join-Path $classic "dumpwow_done.txt"
Remove-Item $ready, $done -ErrorAction SilentlyContinue

Write-Host "Starting dumpwow..."
$dw = Start-Process -FilePath $dumpwow -ArgumentList "`"$(Join-Path $classic 'WowClassic.exe')`"" `
  -PassThru -WindowStyle Normal `
  -WorkingDirectory $classic

# Wait for ready signal
$pidWow = $null
$imageBase = $null
$remapBase = $null
for ($i = 0; $i -lt 180; $i++) {
  if (Test-Path $ready) {
    $lines = Get-Content $ready
    $pidWow = [uint32]$lines[0]
    $imageBase = $lines[1].Trim()
    if ($lines.Count -ge 3) { $remapBase = $lines[2].Trim() }
    Write-Host "Ready: pid=$pidWow image=0x$imageBase remap=0x$remapBase"
    break
  }
  if ($dw.HasExited) { throw "dumpwow exited early code=$($dw.ExitCode)" }
  Start-Sleep -Seconds 1
}
if (-not $pidWow) { throw "Timed out waiting for dumpwow_ready.txt" }

$unpacked = Join-Path $classic "WowClassic_unpacked.exe"
if (-not (Test-Path $unpacked)) { throw "Missing $unpacked" }

# Try x64dbg WOWDump / OverwatchDumpFix (non-blocking launch, short wait)
$scriptPath = Join-Path $cata "wow-dumpwow\tools\wow_iat.x64dbg.txt"
@"
WOWDump
OverwatchDumpFix
"@ | Set-Content -Path $scriptPath -Encoding ASCII

Write-Host "Launching x64dbg attach + WOWDump script..."
$dbg = $null
try {
  $dbg = Start-Process -FilePath $x64dbg -ArgumentList @(
    "-p", "$pidWow",
    "-s", "`"$scriptPath`""
  ) -PassThru -WorkingDirectory (Split-Path $x64dbg)
  Start-Sleep -Seconds 25
} catch {
  Write-Host "x64dbg launch note: $_"
}

# Run Scylla IAT fix against remapped base when available
$searchBase = if ($remapBase -and $remapBase -ne "0") { $remapBase } else { $imageBase }
$outFile = Join-Path $classic "WowClassic_unpacked_SCY.exe"
Write-Host "Running ScyllaIatFix..."
& $fixer $pidWow $unpacked $searchBase $outFile
$fixRc = $LASTEXITCODE
Write-Host "ScyllaIatFix exit=$fixRc"

# Signal dumpwow to exit
Set-Content -Path $done -Value "ok" -Encoding ASCII
Write-Host "Signaled dumpwow_done.txt"

# Give dumpwow a moment to exit; close debugger if we started it
Start-Sleep -Seconds 3
if ($dbg -and -not $dbg.HasExited) {
  Write-Host "Leaving x64dbg running (close it manually if needed). pid=$($dbg.Id)"
}

if (Test-Path $outFile) {
  Get-Item $outFile | Format-Table FullName, Length, LastWriteTime
} else {
  Write-Host "No SCY output produced"
  exit 1
}
