<#
.SYNOPSIS
  Vairav Technology CSOC - "Narrow Grants, Wide Engines" database RCE exposure check for Windows hosts.
  PostgreSQL CVE-2026-116331 | MySQL CVE-2026-101786 | Oracle Text CVE-2026-114819 |
  Oracle REST Data Services CVE-2026-91609 | ClickHouse (no CVE, no confirmed fix)
.DESCRIPTION
  Read-only. Never sends exploit traffic and needs no database login. Checks installed engine versions against
  the fixed releases / affected ranges, stale running binaries, database ports listening on non-loopback
  addresses, and (with -Hunt) local log messages and database services that spawned shells.
  Privilege (TEMPORARY / CREATE TEMPORARY TABLES) checks need SQL access: use the Python script with --sql.
.PARAMETER OracleVersion  Oracle Database release update, e.g. 19.29 (used when sqlplus cannot be run)
.PARAMETER OrdsVersion    ORDS version, e.g. 25.1.0
.PARAMETER OrdsUrl        ORDS URL for a reachability-only check
.PARAMETER Hunt           Search local logs and the process tree for indicators
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\db_rce_check_windows.ps1 -Hunt
.NOTES
  Exit codes: 0 no finding | 1 vulnerable, unsupported or restart required | 2 review / hardening gaps | 3 no database found
#>
[CmdletBinding()]
param([string]$OracleVersion, [string]$OrdsVersion, [string]$OrdsUrl, [switch]$Hunt)
$ErrorActionPreference = 'Continue'
$script:worst = 0; $script:found = $false
function Bump($n) { if ($n -eq 1) { $script:worst = 1 } elseif ($n -eq 2 -and $script:worst -ne 1) { $script:worst = 2 } }
function Say($t, $c = 'White') { Write-Host $t -ForegroundColor $c }
function Note($t) { Say "  $t" }
function Head($engine, $ver, $bin) { $script:found = $true; Write-Host ''; Say "--- $engine  $ver  ($bin) ---" White }
function Verdict($v) {
  $col = switch ($v) { 'PATCHED' {'Green'} 'OUTSIDE-RANGE' {'Green'} 'VULNERABLE' {'Red'} 'UNSUPPORTED' {'Red'} 'RESTART-REQUIRED' {'Red'} 'NOT-LISTED' {'Cyan'} default {'Yellow'} }
  Say "  VERDICT: $v" $col
  if ($v -in 'VULNERABLE','UNSUPPORTED','RESTART-REQUIRED') { Bump 1 } elseif ($v -in 'REVIEW','NO-FIX') { Bump 2 }
}
function VN([int]$a, [int]$b, [int]$c = 0, [int]$d = 0) { return ((([int64]$a * 10000 + $b) * 10000 + $c) * 10000 + $d) }
function Run($exe, $argList) { try { $o = & $exe @argList 2>&1 | ForEach-Object { $_.ToString() }; return ($o -join "`n") } catch { return '' } }
function Test-Stale($bin, $procName) {
  $mt = (Get-Item -LiteralPath $bin).LastWriteTime
  $p = Get-Process -Name $procName -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -eq $bin } catch { $false } } | Sort-Object StartTime | Select-Object -First 1
  return ($p -and $mt -gt $p.StartTime)
}
function Find-Files($patterns) { foreach ($p in $patterns) { Get-ChildItem -Path $p -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } } }

Say '====================================================================' Cyan
Say " Database RCE (Narrow Grants, Wide Engines) check - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" Cyan
Say '====================================================================' Cyan

# ---------------- PostgreSQL
$pgFix = @{ 14 = 25; 15 = 20; 16 = 16; 17 = 12; 18 = 7 }
$svc = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
$pgBins = @(Find-Files @('C:\Program Files\PostgreSQL\*\bin\postgres.exe', 'C:\Program Files (x86)\PostgreSQL\*\bin\postgres.exe', 'D:\PostgreSQL\*\bin\postgres.exe'))
foreach ($s in ($svc | Where-Object { $_.Name -match 'postgres' -and $_.PathName -match '"?([^"]*\\bin)\\pg_ctl\.exe' })) { $pgBins += (Join-Path $Matches[1] 'postgres.exe') }
foreach ($b in ($pgBins | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)) {
  $o = Run $b @('--version'); $v = $null
  if ($o -match '(\d+)\.(\d+)') { $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $v = "$major.$minor" }
  Head 'PostgreSQL' $v $b
  if (-not $v) { Note 'version not parsed'; Verdict 'REVIEW'; continue }
  if ($pgFix.ContainsKey($major)) {
    Note "fixed release for this branch: $major.$($pgFix[$major]) (12 Nov 2026)"
    $vd = if ($minor -ge $pgFix[$major]) { 'PATCHED' } else { 'VULNERABLE' }
  } elseif ($major -lt 14) { $vd = 'UNSUPPORTED'; Note 'end-of-life branch: no fixed release; upgrade to 18.7 / 17.12 / 16.16 / 15.20 / 14.25 or newer' }
  else { $vd = 'REVIEW'; Note 'branch not in the advisory; confirm it includes the November 2026 fixes' }
  if ($vd -eq 'PATCHED' -and (Test-Stale $b 'postgres')) { $vd = 'RESTART-REQUIRED'; Note 'running postgres.exe is older than the binary on disk: restart the PostgreSQL service' }
  Verdict $vd
}

# ---------------- MySQL / MariaDB
$myBins = @(Find-Files @('C:\Program Files\MySQL\MySQL Server*\bin\mysqld.exe', 'C:\Program Files\MariaDB*\bin\mysqld.exe', 'C:\Program Files\MariaDB*\bin\mariadbd.exe', 'C:\mysql*\bin\mysqld.exe'))
foreach ($s in ($svc | Where-Object { $_.Name -match 'mysql|mariadb' -and $_.PathName -match '"([^"]*mysqld\.exe|[^"]*mariadbd\.exe)"' })) { $myBins += $Matches[1] }
foreach ($b in ($myBins | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique)) {
  $first = (Run $b @('--version')).Trim().Split("`n")[0]
  if ($first -match 'mariadb' -or $b -match 'MariaDB|mariadbd') { Head 'MariaDB' '' $b; Note $first; Note 'MariaDB is not covered by the advisory'; Verdict 'NOT-LISTED'; continue }
  $v = $null; if ($first -match 'Ver\s+(\d+)\.(\d+)\.(\d+)') { $v = "$($Matches[1]).$($Matches[2]).$($Matches[3])"; $n = VN $Matches[1] $Matches[2] $Matches[3] }
  Head 'MySQL' $v $b; Note $first
  if (-not $v) { $vd = 'REVIEW'; Note 'version not parsed' }
  elseif ($n -ge (VN 26 7 0) -and $n -le (VN 26 7 1)) { $vd = 'VULNERABLE'; Note 'CVE-2026-101786: affected range 26.7.0-26.7.1; apply the 20 Oct 2026 Oracle MySQL update' }
  else { $vd = 'OUTSIDE-RANGE'; Note "not in the advisory's affected range (26.7.0-26.7.1); exact fixed build not published in reviewed sources - confirm against Oracle's October 2026 CPU"
         if (Test-Stale $b 'mysqld') { $vd = 'RESTART-REQUIRED'; Note 'running mysqld.exe is older than the binary on disk: restart MySQL' } }
  Verdict $vd
}

# ---------------- Oracle Database
$homes = @()
if ($env:ORACLE_HOME) { $homes += $env:ORACLE_HOME }
foreach ($k in (Get-ChildItem 'HKLM:\SOFTWARE\ORACLE' -ErrorAction SilentlyContinue)) { $h = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ORACLE_HOME; if ($h) { $homes += $h } }
$oraSeen = $false
function Eval-Oracle($label, $ver) {
  $script:oraSeen = $true
  $p = $ver -split '\.'; $maj = [int]$p[0]; $mnr = [int]$p[1]; $pp = if ($p.Count -gt 2) { [int]$p[2] } else { 0 }
  Head 'Oracle Database' $ver $label
  if (($maj -eq 19 -and $mnr -le 32) -or ($maj -eq 21 -and $mnr -le 24) -or ($maj -eq 23 -and (VN 23 $mnr $pp) -ge (VN 23 4 0) -and (VN 23 $mnr $pp) -le (VN 23 26 3))) {
    $vd = 'VULNERABLE'; Note 'CVE-2026-114819 (Oracle Text, CVSS 9.9): affected 19.3-19.32 / 21.3-21.24 / 23.4.0-23.26.3; apply the November 2026 CPU (17 Nov)'
    Note "version comes from sqlplus -V (the home's release update); confirm with 'opatch lspatches' - an interim patch may cover it"
  } elseif ($maj -in 19, 21, 23) { $vd = 'OUTSIDE-RANGE'; Note "above the advisory's affected range; confirm the November 2026 CPU is in the home with opatch lspatches" }
  else { $vd = 'REVIEW'; Note 'release not covered by the advisory (likely out of support); confirm with Oracle' }
  Verdict $vd
}
foreach ($h in ($homes | Select-Object -Unique)) {
  $sp = Join-Path $h 'bin\sqlplus.exe'
  if (Test-Path -LiteralPath $sp) { $o = Run $sp @('-V'); if ($o -match 'Version\s+(\d+\.\d+\.\d+)') { Eval-Oracle $h $Matches[1] } }
}
if ($OracleVersion) { Eval-Oracle '(-OracleVersion)' $OracleVersion }
if (-not $oraSeen -and ($homes.Count -gt 0 -or ($svc | Where-Object { $_.Name -match '^OracleService' }))) {
  Head 'Oracle Database' '' (($homes | Select-Object -Unique) -join ','); Note 'Oracle detected but version not read; run sqlplus -V in the home or pass -OracleVersion'; Verdict 'REVIEW' }

# ---------------- ORDS
function Eval-Ords($label, $ver) {
  Head 'Oracle REST Data Services' $ver $label
  if ($ver -match '^(\d+)\.(\d+)\.(\d+)') { $n = VN $Matches[1] $Matches[2] $Matches[3]
    if ($n -ge (VN 24 2 0) -and $n -le (VN 26 2 1)) { $vd = 'VULNERABLE'; Note 'CVE-2026-91609 (GraphQL): affected 24.2.0-26.2.1; apply the October 2026 CPU. Part of the unauthenticated Oracle chain' }
    elseif ($n -lt (VN 24 2 0)) { $vd = 'REVIEW'; Note 'older than the listed range; out of support - upgrade' }
    else { $vd = 'OUTSIDE-RANGE'; Note "above the advisory's affected range" }
  } else { $vd = 'REVIEW'; Note 'version not parsed' }
  Verdict $vd
}
$ordsBins = @(); $cmd = Get-Command ords -ErrorAction SilentlyContinue; if ($cmd) { $ordsBins += $cmd.Source }
$ordsBins += @(Find-Files @('C:\oracle\ords\bin\ords.cmd', 'C:\ords\bin\ords.cmd', 'D:\ords\bin\ords.cmd'))
foreach ($b in ($ordsBins | Select-Object -Unique)) { $o = Run $b @('--version'); $v = if ($o -match '(\d+\.\d+\.\d+)') { $Matches[1] } else { '' }; Eval-Ords $b $v }
if ($OrdsVersion) { Eval-Ords '(-OrdsVersion)' $OrdsVersion }
foreach ($w in (Get-ChildItem -Path 'C:\oracle', 'C:\ords', 'D:\ords', 'C:\Program Files\Apache*' -Filter ords.war -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5)) {
  Head 'Oracle REST Data Services' '' $w.FullName; Note "ords.war found (Tomcat/WebLogic deployment): read its version with 'java -jar ords.war version' or pass -OrdsVersion"; Verdict 'REVIEW' }

# ---------------- ClickHouse
foreach ($b in (Find-Files @('C:\ClickHouse\clickhouse*.exe', 'C:\Program Files\ClickHouse\clickhouse*.exe') | Select-Object -Unique)) {
  $o = Run $b @('--version'); $v = if ($o -match '(\d+\.\d+\.\d+(\.\d+)?)') { $Matches[1] } else { '' }
  Head 'ClickHouse' $v $b; Note 'no CVE and no confirmed vendor fix; researcher tested 26.7.5.10 (shell obtained via format_binary_max_string_size = 0)'
  Say '  [BAD] add a read-only constraint on format_binary_max_string_size in the users profile (Vairav interim suggestion); check config files manually' Red; Bump 2
  Verdict 'NO-FIX' }

# ---------------- listeners
Write-Host ''; Say '--- Database ports listening ---' White
$ports = @{ 5432 = 'PostgreSQL'; 3306 = 'MySQL'; 33060 = 'MySQL X'; 1521 = 'Oracle listener'; 8123 = 'ClickHouse HTTP'; 9000 = 'ClickHouse native'; 9440 = 'ClickHouse TLS'; 8443 = 'HTTPS (ORDS?)' }
$shown = $false
try {
  Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $ports.ContainsKey([int]$_.LocalPort) } | Sort-Object LocalPort, LocalAddress -Unique | ForEach-Object {
    $shown = $true; $lo = $_.LocalAddress -in '127.0.0.1', '::1'
    if ($lo) { Say ("  {0,-18} {1}:{2}  loopback only" -f $ports[[int]$_.LocalPort], $_.LocalAddress, $_.LocalPort) Green }
    else { Say ("  {0,-18} {1}:{2}  NETWORK-REACHABLE: restrict to app servers/admin hosts" -f $ports[[int]$_.LocalPort], $_.LocalAddress, $_.LocalPort) Red; Bump 2 } }
} catch { Say '  could not read listeners (Get-NetTCPConnection unavailable)' Yellow; $shown = $true }
if (-not $shown) { Say '  none of the standard database ports found listening' }

# ---------------- ORDS URL
if ($OrdsUrl) { Write-Host ''; Say '--- ORDS URL (reachability only) ---' White
  try { $skip = @{}; if ($PSVersionTable.PSVersion.Major -ge 7) { $skip.SkipCertificateCheck = $true }
        $r = Invoke-WebRequest -Uri $OrdsUrl -Method Get -TimeoutSec 8 -UseBasicParsing @skip -ErrorAction Stop
        Say "  $OrdsUrl reachable (HTTP $($r.StatusCode)) - confirm it is not exposed to untrusted networks; patch ORDS and Oracle" Yellow; Bump 2 }
  catch { Say "  ${OrdsUrl}: $($_.Exception.Message)" } }

# ---------------- hunt
if ($Hunt) {
  Write-Host ''; Say '--- Hunt (local logs; review dates against 20 Oct 2026 onward) ---' White; $hits = $false
  $logs = Find-Files @('C:\Program Files\PostgreSQL\*\data\log\*', 'C:\Program Files\PostgreSQL\*\data\pg_log\*', 'C:\ProgramData\MySQL\MySQL Server*\Data\*.err', 'C:\Program Files\MySQL\MySQL Server*\data\*.err')
  foreach ($f in $logs) {
    Select-String -Path $f -Pattern 'terminated by signal|got signal 11|exception.*ACCESS_VIOLATION|format_binary_max_string_size|CREATE AGGREGATE.*SORTOP' -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object {
      $hits = $true; $l = $_.Line.Trim(); if ($l.Length -gt 200) { $l = $l.Substring(0, 200) }; Say "  ${f}: $l" Yellow } }
  $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue; $byId = @{}; foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
  $sus = 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'curl.exe', 'wget.exe', 'python.exe', 'certutil.exe', 'bitsadmin.exe'
  foreach ($p in ($procs | Where-Object { $sus -contains $_.Name })) {
    $par = $byId[[int]$p.ParentProcessId]
    if ($par -and $par.Name -match '^(postgres|mysqld|mariadbd|oracle|tnslsnr|clickhouse)') { Say "  PID $($p.ProcessId): $($par.Name) spawned $($p.Name)  $($p.CommandLine)" Red; Bump 1; $hits = $true } }
  if ($hits) { Bump 2 } else { Say '  nothing suspicious found in local logs or process tree' Green }
}

Write-Host ''
Say 'Note: heuristics only. Version checks cannot prove a host is safe. For TEMPORARY / CREATE TEMPORARY TABLES privilege checks use the Python script with --sql.'
if (-not $script:found) { Say '[i] No PostgreSQL, MySQL, Oracle, ORDS or ClickHouse installation found.' Cyan; exit 3 }
exit $script:worst
