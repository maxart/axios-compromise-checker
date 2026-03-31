<#
.SYNOPSIS
    Axios supply chain attack (CVE-2025-XXXXX) detection and response script.
    Targets WSL + Windows environments.

.DESCRIPTION
    Scans for indicators of compromise from the malicious axios@1.14.1 / axios@0.30.4
    npm packages, checks for dropped payloads, inspects DNS cache and network connections,
    and offers guided cleanup.

.NOTES
    Run from an elevated (Administrator) PowerShell prompt for full coverage.
    The script is non-destructive by default - it reports findings and prompts before acting.
#>

param(
    [switch]$ScanOnly,
    [switch]$AutoClean
)

$ErrorActionPreference = "Continue"

# --- Constants -----------------------------------------------------------

$C2Domain   = "sfrclak.com"
$C2IP       = "142.11.206.73"
$WinPayload = Join-Path $env:PROGRAMDATA "wt.exe"
$WinTempVbs = Join-Path $env:TEMP "6202033.vbs"
$WinTempPs1 = Join-Path $env:TEMP "6202033.ps1"
$LinuxPayload = "/tmp/ld.py"
$MacPayload = "/Library/Caches/com.apple.act.mond"
$MaliciousPkg = "plain-crypto-js"
$BadAxiosVersions = @("1.14.1", "0.30.4")

$Findings = [System.Collections.Generic.List[string]]::new()

# --- Helpers -------------------------------------------------------------

function Write-Banner {
    param([string]$Text)
    $sep = "-" * 60
    Write-Host ""
    Write-Host $sep -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $sep -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Text)
    Write-Host "  [OK]    $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  [WARN]  $Text" -ForegroundColor Yellow
    $script:Findings.Add($Text)
}

function Write-Danger {
    param([string]$Text)
    Write-Host "  [!!]    $Text" -ForegroundColor Red
    $script:Findings.Add($Text)
}

function Prompt-Action {
    param([string]$Message)
    if ($AutoClean) { return $true }
    if ($ScanOnly)  { return $false }
    $reply = Read-Host "  $Message (y/N)"
    return $reply -match '^[Yy]'
}

# --- 1. Windows payload --------------------------------------------------

Write-Banner "Checking for Windows RAT payload"

if (Test-Path $WinPayload) {
    Write-Danger "FOUND dropped payload: $WinPayload"

    # Check if running
    $proc = Get-Process -Name "wt" -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -eq $WinPayload }
    if ($proc) {
        Write-Danger "Payload is RUNNING (PID $($proc.Id))"
        if (Prompt-Action "Kill the process?") {
            Stop-Process -Id $proc.Id -Force
            Write-Ok "Process killed"
        }
    }

    if (Prompt-Action "Delete $WinPayload?") {
        Remove-Item -Path $WinPayload -Force
        Write-Ok "Payload deleted"
    }
} else {
    Write-Ok "No Windows payload at $WinPayload"
}

# Windows temp dropper files (self-delete, but check anyway)
foreach ($tempFile in @($WinTempVbs, $WinTempPs1)) {
    if (Test-Path $tempFile) {
        Write-Danger "FOUND dropper artifact: $tempFile"
        if (Prompt-Action "Delete $tempFile?") {
            Remove-Item -Path $tempFile -Force
            Write-Ok "Deleted $tempFile"
        }
    } else {
        Write-Ok "No dropper at $tempFile"
    }
}

# --- 2. WSL / Linux / macOS payload ---------------------------------------

Write-Banner "Checking for WSL / Linux payload"

$wslInstalled = Get-Command wsl -ErrorAction SilentlyContinue
if ($wslInstalled) {
    $wslCheck = wsl -e sh -c "if [ -f '$LinuxPayload' ]; then echo FOUND; else echo CLEAN; fi" 2>$null
    if ($wslCheck -match "FOUND") {
        Write-Danger "FOUND dropped payload in WSL: $LinuxPayload"
        if (Prompt-Action "Delete $LinuxPayload inside WSL?") {
            wsl -e rm -f $LinuxPayload
            Write-Ok "WSL payload deleted"
        }
    } else {
        Write-Ok "No WSL payload at $LinuxPayload"
    }

    # Check for active connections to C2 inside WSL
    $wslNetC2 = wsl -e sh -c "ss -tnp 2>/dev/null | grep '$C2IP' || true"
    if ($wslNetC2) {
        Write-Danger "Active WSL connection to C2 IP $C2IP detected"
        Write-Host $wslNetC2
    }
} else {
    Write-Ok "WSL not installed - skipping Linux checks"
}

# --- macOS payload (only reachable if this is somehow run on macOS) -------

if (Test-Path $MacPayload) {
    Write-Danger "FOUND macOS payload: $MacPayload"
    if (Prompt-Action "Delete $MacPayload?") {
        Remove-Item -Path $MacPayload -Force
        Write-Ok "macOS payload deleted"
    }
} elseif ($IsMacOS) {
    Write-Ok "No macOS payload at $MacPayload"
}

# --- 3. Network indicators ------------------------------------------------

Write-Banner "Checking network indicators"

# DNS cache
try {
    $dnsHit = Get-DnsClientCache -ErrorAction SilentlyContinue |
              Where-Object { $_.Entry -match $C2Domain }
    if ($dnsHit) {
        # Filter out entries blocked via hosts file (resolve to 0.0.0.0 or 127.0.0.1)
        $liveHits = @($dnsHit | Where-Object {
            $_.Data -and $_.Data -ne '0.0.0.0' -and $_.Data -ne '127.0.0.1'
        })
        if ($liveHits.Count -gt 0) {
            Write-Danger "C2 domain '$C2Domain' found in DNS cache"
        } else {
            Write-Ok "C2 domain in DNS cache but blocked (hosts file redirect)"
        }
    } else {
        Write-Ok "C2 domain not in DNS cache"
    }
} catch {
    Write-Host "  [SKIP]  Could not read DNS cache (requires elevation)" -ForegroundColor DarkGray
}

# Active TCP connections to C2 IP
$c2Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
                 Where-Object { $_.RemoteAddress -eq $C2IP }
if ($c2Connections) {
    Write-Danger "Active TCP connection(s) to C2 IP $C2IP"
    $c2Connections | Format-Table -Property LocalPort, RemotePort, State, OwningProcess -AutoSize
} else {
    Write-Ok "No active connections to C2 IP"
}

# Hosts file / firewall check
$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$hostsBlocked = Select-String -Path $hostsPath -Pattern $C2Domain -ErrorAction SilentlyContinue
if ($hostsBlocked) {
    Write-Ok "C2 domain is already blocked in hosts file"
} else {
    Write-Warn "C2 domain is NOT blocked in hosts file"
    if (Prompt-Action "Add '$C2Domain' block to hosts file? (requires elevation)") {
        try {
            Add-Content -Path $hostsPath -Value "`n# Axios supply chain attack C2 block`n0.0.0.0 $C2Domain" -ErrorAction Stop
            Write-Ok "Hosts file updated"
        } catch {
            Write-Warn "Failed to update hosts file - run as Administrator"
        }
    }
}

# --- 4. Scan node_modules trees ------------------------------------------

Write-Banner "Scanning for compromised npm packages"

# Collect project dirs: scan common locations + current dir
$searchRoots = @($PWD.Path)
if ($env:USERPROFILE) {
    @("Projects", "repos", "src", "dev", "Work", "code", "Desktop") | ForEach-Object {
        $p = Join-Path $env:USERPROFILE $_
        if (Test-Path $p) { $searchRoots += $p }
    }
}

# Also scan inside WSL home
$wslProjects = @()
if ($wslInstalled) {
    $wslHome = (wsl -e sh -c 'echo $HOME') 2>$null
    if ($wslHome) {
        $wslProjects = (wsl -e sh -c "find $wslHome -maxdepth 4 -name 'package-lock.json' -o -name 'pnpm-lock.yaml' 2>/dev/null") 2>$null
    }
}

$compromisedProjects = [System.Collections.Generic.List[string]]::new()

# Windows scan
foreach ($root in $searchRoots) {
    Write-Host "  Scanning $root ..." -ForegroundColor DarkGray
    $lockfiles = Get-ChildItem -Path $root -Recurse -Depth 5 -Include "package-lock.json","pnpm-lock.yaml","yarn.lock" -ErrorAction SilentlyContinue

    foreach ($lf in $lockfiles) {
        $projectDir = $lf.DirectoryName
        $content = Get-Content $lf.FullName -Raw -ErrorAction SilentlyContinue

        # Check for phantom dependency
        if ($content -match $MaliciousPkg) {
            Write-Danger "plain-crypto-js found in $($lf.FullName)"
            $compromisedProjects.Add($projectDir)
        }

        # Check for bad axios versions
        foreach ($v in $BadAxiosVersions) {
            if ($content -match "axios.*$v") {
                Write-Danger "axios@$v found in $($lf.FullName)"
                if (-not $compromisedProjects.Contains($projectDir)) {
                    $compromisedProjects.Add($projectDir)
                }
            }
        }
    }
}

# WSL scan
if ($wslProjects) {
    foreach ($lf in $wslProjects) {
        $lf = $lf.Trim()
        if (-not $lf) { continue }
        Write-Host "  Scanning (WSL) $lf ..." -ForegroundColor DarkGray
        $content = wsl -e cat $lf 2>$null
        if ($content -match $MaliciousPkg) {
            Write-Danger "[WSL] plain-crypto-js found in $lf"
        }
        foreach ($v in $BadAxiosVersions) {
            if ($content -match "axios.*$v") {
                Write-Danger "[WSL] axios@$v found in $lf"
            }
        }
    }
}

if ($compromisedProjects.Count -eq 0) {
    Write-Ok "No compromised axios versions found in scanned projects"
}

# --- 5. Cleanup compromised projects -------------------------------------

if ($compromisedProjects.Count -gt 0 -and -not $ScanOnly) {
    Write-Banner "Cleaning compromised projects"

    foreach ($dir in $compromisedProjects) {
        Write-Host ""
        Write-Host "  Project: $dir" -ForegroundColor White

        if (Prompt-Action "Clean this project? (rm node_modules, reinstall with --ignore-scripts)") {
            $nmPath = Join-Path $dir "node_modules"
            $pcjPath = Join-Path $nmPath $MaliciousPkg

            # Remove phantom dependency first
            if (Test-Path $pcjPath) {
                Remove-Item -Path $pcjPath -Recurse -Force
                Write-Ok "Removed $MaliciousPkg"
            }

            # Full clean reinstall
            Remove-Item -Path $nmPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Ok "Removed node_modules"

            Push-Location $dir
            & npm install axios@1.14.0 --save 2>$null
            & npm ci --ignore-scripts 2>$null
            Pop-Location
            Write-Ok "Reinstalled with --ignore-scripts"
        }
    }
}

# --- 6. npmrc hardening ---------------------------------------------------

Write-Banner "Checking npmrc hardening"

$npmrcPath = Join-Path $env:USERPROFILE ".npmrc"
$npmrcExists = Test-Path $npmrcPath
$hasIgnoreScripts = $false
$hasMinAge = $false

if ($npmrcExists) {
    $npmrcContent = Get-Content $npmrcPath -Raw
    $hasIgnoreScripts = $npmrcContent -match "ignore-scripts\s*=\s*true"
    $hasMinAge = $npmrcContent -match "min-release-age"
}

if ($hasIgnoreScripts) {
    Write-Ok "ignore-scripts=true is set in .npmrc"
} else {
    Write-Warn "ignore-scripts is not set - postinstall attacks can execute"
}

if ($hasMinAge) {
    Write-Ok "min-release-age is set in .npmrc"
} else {
    Write-Warn "min-release-age is not set - new malicious publishes install immediately"
}

if ((-not $hasIgnoreScripts -or -not $hasMinAge) -and (Prompt-Action "Harden .npmrc with ignore-scripts=true and min-release-age=7?")) {
    $additions = @()
    if (-not $hasIgnoreScripts) { $additions += "ignore-scripts=true" }
    if (-not $hasMinAge) { $additions += "min-release-age=7" }
    $block = "`n# Axios incident hardening ($(Get-Date -Format yyyy-MM-dd))`n" + ($additions -join "`n")

    if ($npmrcExists) {
        Add-Content -Path $npmrcPath -Value $block
    } else {
        Set-Content -Path $npmrcPath -Value $block.TrimStart()
    }
    Write-Ok ".npmrc updated"
}

# WSL npmrc
if ($wslInstalled) {
    $wslNpmrc = wsl -e sh -c 'cat ~/.npmrc 2>/dev/null || echo __MISSING__'
    # Join array output into a single string so -match returns a boolean, not filtered elements
    $wslNpmrcStr = if ($wslNpmrc -is [array]) { $wslNpmrc -join "`n" } else { "$wslNpmrc" }

    $wslMissing = $wslNpmrcStr -match "__MISSING__"
    $wslHasIgnoreScripts = (-not $wslMissing) -and ($wslNpmrcStr -match "ignore-scripts\s*=\s*true")
    $wslHasMinAge = (-not $wslMissing) -and ($wslNpmrcStr -match "min-release-age")

    if ($wslHasIgnoreScripts) {
        Write-Ok "WSL: ignore-scripts=true is set in .npmrc"
    } else {
        Write-Warn "WSL ~/.npmrc is missing ignore-scripts=true"
    }

    if ($wslHasMinAge) {
        Write-Ok "WSL: min-release-age is set in .npmrc"
    } else {
        Write-Warn "WSL ~/.npmrc is missing min-release-age"
    }

    if ((-not $wslHasIgnoreScripts -or -not $wslHasMinAge) -and (Prompt-Action "Harden WSL ~/.npmrc?")) {
        $additions = @()
        if (-not $wslHasIgnoreScripts) { $additions += "ignore-scripts=true" }
        if (-not $wslHasMinAge) { $additions += "min-release-age=7" }
        $block = "\n# Axios incident hardening\n" + ($additions -join "\n") + "\n"
        wsl -e sh -c "printf '$block' >> ~/.npmrc"
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "WSL .npmrc updated"
        } else {
            Write-Warn "Failed to update WSL .npmrc"
        }
    }
}

# --- 7. Summary -----------------------------------------------------------

Write-Banner "Summary"

if ($Findings.Count -eq 0) {
    Write-Host ""
    Write-Host "  No indicators of compromise found." -ForegroundColor Green
    Write-Host "  Your environment appears clean." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  $($Findings.Count) finding(s):" -ForegroundColor Yellow
    Write-Host ""
    $i = 1
    foreach ($f in $Findings) {
        Write-Host "  $i. $f" -ForegroundColor Yellow
        $i++
    }
    Write-Host ""
    Write-Danger "ACTION REQUIRED: Rotate all credentials accessible from this machine"
    Write-Host @"

  Rotate these immediately:
    - npm tokens          (npm token revoke / regenerate)
    - SSH keys            (regenerate, remove old pubkeys from GitHub/servers)
    - Cloud credentials   (AWS, GCP, Azure)
    - CI/CD secrets       (GitHub Actions, GitLab CI, etc.)
    - Database passwords
    - API keys / service tokens
    - Browser-stored passwords (if RAT persisted)

  If wt.exe was found and running, consider a full OS reinstall.
"@ -ForegroundColor Red
}

Write-Host ""
