# Harden-Windows.ps1
# WinGuard Windows Hardening Toolkit
# IS2083 Advanced Scripting - Lab 2
#
# PURPOSE
#   Audits Windows 11 security settings against a representative set of
#   Microsoft Security Baseline controls and additional hardening controls.
#   Apply mode remediates supported failures and performs a follow-up audit.
#
# OPERATING MODES
#   Audit - evaluates configured controls without intentionally changing settings.
#   Apply - performs a baseline audit, remediates supported failures, and re-audits.
#
# REPORTING
#   Results are grouped by control category, scored using weighted checks, and
#   written to a timestamped text report under the current user's profile.
#
# CONTROL STRUCTURE
#   Each New-Check entry defines a category, control name, audit script block,
#   optional remediation script block, and score weight. A null remediation block
#   marks an audit-only control.

param(
    [ValidateSet('Audit','Apply')]
    [string]$Mode = 'Audit'
)

# ======================= Tool configuration =======================
$ToolName = 'WinGuard'
# ================================================================

# Category labels used for grouping controls in console output and reports.
$BASELINE = 'Microsoft Security Baseline'
$ADVANCED = 'Advanced hardening'

# Stores registered security control definitions.
$script:Checks = @()

# ---------- Helper: administrator privilege check ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- Helper: completion/start notification ----------
function Show-Popup {
    param([string]$Message, [string]$Title)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title)
    } catch {
        Write-Host ('[' + $Title + '] ' + $Message) -ForegroundColor Magenta
    }
}

# ---------- Helper: security score rating ----------
function Get-Rating {
    param([int]$Score)
    if ($Score -ge 85)      { return 'STRONG' }
    elseif ($Score -ge 60)  { return 'MODERATE' }
    else                    { return 'NEEDS WORK' }
}

# ---------- Helper: security control registration ----------
# New-Check stores the audit test, optional remediation action, and score weight.
# A null Remediate block identifies an audit-only control.
function New-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Remediate,
        [int]$Weight = 10
    )
    $script:Checks += [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Test      = $Test
        Remediate = $Remediate
        Weight    = $Weight
    }
}

# ================================================================
#  Microsoft Security Baseline controls  (category: $BASELINE)
# ================================================================

# SMBv1 protocol disabled.
New-Check $BASELINE 'SMBv1 disabled' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool](-not $c.EnableSMB1Protocol); Detail = "EnableSMB1Protocol=$($c.EnableSMB1Protocol)" }
} {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
} 10

# SMB server signing required.
New-Check $BASELINE 'SMB server signing required' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
} {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
} 10

# NTLM hardened - refuse LM and NTLMv1.
New-Check $BASELINE 'NTLM hardened (LmCompatibilityLevel = 5)' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    @{ Pass = ($v -eq 5); Detail = "LmCompatibilityLevel=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
} 10

# User Account Control enabled.
New-Check $BASELINE 'UAC enabled' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    @{ Pass = ($v -eq 1); Detail = "EnableLUA=$v" }
} {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord
} 10

# Minimum password length 14 or more.
New-Check $BASELINE 'Minimum password length 14 or more' {
    $line = net accounts | Select-String 'Minimum password length'
    $value = [int](($line -split ':')[-1].Trim())
    @{ Pass = ($value -ge 14); Detail = "Minimum password length=$value" }
} {
    net accounts /minpwlen:14 | Out-Null
} 10

# Account lockout threshold from 1 to 10.
New-Check $BASELINE 'Account lockout threshold 1 to 10' {
    $line = net accounts | Select-String 'Lockout threshold'
    $text = (($line -split ':')[-1].Trim())
    if ($text -match '^\d+$') {
        $value = [int]$text
        @{ Pass = ($value -ge 1 -and $value -le 10); Detail = "Lockout threshold=$value" }
    } else {
        @{ Pass = $false; Detail = "Lockout threshold=$text" }
    }
} {
    net accounts /lockoutthreshold:10 | Out-Null
} 10

# Windows Firewall enabled on all profiles.
New-Check $BASELINE 'Firewall enabled on all profiles' {
    $profiles = Get-NetFirewallProfile
    $allEnabled = ($profiles.Enabled -notcontains $false)
    $detail = ($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', '
    @{ Pass = $allEnabled; Detail = $detail }
} {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
} 10

# Microsoft Defender real-time protection enabled.
New-Check $BASELINE 'Defender real-time protection on' {
    $p = Get-MpPreference
    $disabled = [bool]$p.DisableRealtimeMonitoring
    @{ Pass = (-not $disabled); Detail = "DisableRealtimeMonitoring=$disabled" }
} {
    Set-MpPreference -DisableRealtimeMonitoring $false
} 10

# Built-in Guest account disabled.
New-Check $BASELINE 'Guest account disabled' {
    $guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
    if ($null -eq $guest) {
        @{ Pass = $true; Detail = 'Guest account not present' }
    } else {
        @{ Pass = (-not $guest.Enabled); Detail = "GuestEnabled=$($guest.Enabled)" }
    }
} {
    Disable-LocalUser -Name Guest
} 10

# Remote Desktop requires Network Level Authentication.
New-Check $BASELINE 'RDP requires Network Level Authentication' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    @{ Pass = ($v -eq 1); Detail = "UserAuthentication=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord
} 10

# ================================================================
#  Advanced controls (beyond the baseline)  (category: $ADVANCED)
# ================================================================

# Defender potentially unwanted application protection.
New-Check $ADVANCED 'Defender PUA protection on' {
    $p = Get-MpPreference
    $value = $p.PUAProtection
    @{ Pass = ($value -eq 1); Detail = "PUAProtection=$value" }
} {
    Set-MpPreference -PUAProtection 1
} 8

# Attack Surface Reduction: block Office applications from creating child processes.
New-Check $ADVANCED 'ASR: block Office child processes' {
    $id = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
    $p = Get-MpPreference
    if ($null -eq $p.AttackSurfaceReductionRules_Ids) {
        @{ Pass = $false; Detail = 'ASR rule not configured' }
    } else {
        $index = [Array]::IndexOf([array]$p.AttackSurfaceReductionRules_Ids, $id)
        if ($index -ge 0) {
            $action = [array]$p.AttackSurfaceReductionRules_Actions
            @{ Pass = ($action[$index] -eq 1); Detail = "ASR action=$($action[$index])" }
        } else {
            @{ Pass = $false; Detail = 'ASR rule not configured' }
        }
    }
} {
    Add-MpPreference -AttackSurfaceReductionRules_Ids 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' -AttackSurfaceReductionRules_Actions Enabled
} 8

# PowerShell script block logging enabled.
New-Check $ADVANCED 'PowerShell script block logging on' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    @{ Pass = ($v -eq 1); Detail = "EnableScriptBlockLogging=$v" }
} {
    New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
} 8

# Local Security Authority protection enabled (RunAsPPL).
New-Check $ADVANCED 'LSA protection (RunAsPPL) on' {
    $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    @{ Pass = ($v -eq 1); Detail = "RunAsPPL=$v" }
} {
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
} 8

# BitLocker status on the system drive (audit only).
New-Check $ADVANCED 'BitLocker on system drive' {
    try {
        $b = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $status = $b.ProtectionStatus
        @{ Pass = ($status -eq 'On'); Detail = "ProtectionStatus=$status" }
    } catch {
        @{ Pass = $false; Detail = "BitLocker unavailable: $($_.Exception.Message)" }
    }
} $null 6

# ================================================================
#  Audit, remediation, and reporting engine
# ================================================================

# Executes each registered control, prints grouped results, and calculates the weighted score.
function Invoke-Audit {
    param([string]$Label = '')

    $results = @()
    foreach ($c in $script:Checks) {
        try {
            $r = & $c.Test
        } catch {
            $r = @{ Pass = $false; Detail = ('error: ' + $_.Exception.Message) }
        }
        $results += [pscustomobject]@{
            Category = $c.Category
            Name     = $c.Name
            Pass     = [bool]$r.Pass
            Detail   = [string]$r.Detail
            Weight   = [int]$c.Weight
        }
    }

    $total  = ($script:Checks | Measure-Object -Property Weight -Sum).Sum
    $earned = (@($results | Where-Object { $_.Pass }) | Measure-Object -Property Weight -Sum).Sum
    if (-not $total)  { $total  = 1 }
    if (-not $earned) { $earned = 0 }
    $score  = [math]::Round(($earned / $total) * 100)
    $rating = Get-Rating -Score $score

    $header = '=== Windows Security Audit ==='
    if ($Label) { $header = $header + '  [' + $Label + ']' }
    Write-Host ''
    Write-Host $header -ForegroundColor Cyan

    foreach ($cat in @($BASELINE, $ADVANCED)) {
        $catResults = @($results | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }
        $catPass = @($catResults | Where-Object { $_.Pass }).Count
        Write-Host ''
        Write-Host ('-- ' + $cat + '  (' + $catPass + ' of ' + $catResults.Count + ' passing) --') -ForegroundColor White
        foreach ($x in $catResults) {
            if ($x.Pass) {
                Write-Host ('  [PASS] ' + $x.Name) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] ' + $x.Name + '  ->  ' + $x.Detail) -ForegroundColor Red
            }
        }
    }

    Write-Host ''
    Write-Host ('Security score: ' + $score + ' / 100   (' + $rating + ')') -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]@{
        Label   = $Label
        Results = $results
        Earned  = $earned
        Total   = $total
        Score   = $score
        Rating  = $rating
    }
}

# Attempts to create a restore point, then remediates failing controls with defined fixes.
function Invoke-Apply {
    $actions = @()

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description ('Before ' + $ToolName + ' hardening') -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $actions += 'Created a System Restore Point before remediation.'
    } catch {
        $actions += 'Could not create a restore point; remediation continued.'
    }

    foreach ($c in $script:Checks) {
        if ($null -eq $c.Remediate) { continue }
        try { $r = & $c.Test } catch { $r = @{ Pass = $false } }
        if ([bool]$r.Pass) { continue }
        try {
            & $c.Remediate
            $note = 'Remediated: ' + $c.Name
            if ($c.Name -match 'UAC' -or $c.Name -match 'LSA') {
                $note = $note + '   (reboot required to take effect)'
            }
            $actions += $note
        } catch {
            $actions += ('Remediation failed: ' + $c.Name + '  ->  ' + $_.Exception.Message)
        }
    }

    return $actions
}

# Writes a timestamped grouped report and returns the report path.
function Write-Report {
    param([array]$Summaries, [array]$Actions)

    $dir = Join-Path $env:USERPROFILE ($ToolName + '_reports')
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path  = Join-Path $dir ($ToolName + '_report_' + $stamp + '.txt')

    $lines = @()
    $lines += ($ToolName + ' Security Report')
    $lines += ('Generated: ' + (Get-Date))
    $lines += ('Computer:  ' + $env:COMPUTERNAME)
    $lines += ''

    foreach ($s in $Summaries) {
        $title = 'AUDIT'
        if ($s.Label) { $title = $s.Label }
        $lines += ('===== ' + $title + ' =====')
        foreach ($cat in @($BASELINE, $ADVANCED)) {
            $cr = @($s.Results | Where-Object { $_.Category -eq $cat })
            if ($cr.Count -eq 0) { continue }
            $cp = @($cr | Where-Object { $_.Pass }).Count
            $lines += ''
            $lines += ('-- ' + $cat + '  (' + $cp + ' of ' + $cr.Count + ' passing) --')
            foreach ($x in $cr) {
                $flag = '[FAIL]'
                if ($x.Pass) { $flag = '[PASS]' }
                $lines += ('  ' + $flag + ' ' + $x.Name + '  ->  ' + $x.Detail)
            }
        }
        $lines += ''
        $lines += ('Security score: ' + $s.Score + ' / 100  (' + $s.Rating + ')')
        $lines += ''
    }

    if ($Actions -and $Actions.Count -gt 0) {
        $lines += '===== Applying hardening ====='
        foreach ($a in $Actions) { $lines += ('  ' + $a) }
        $lines += ''
    }

    $lines | Out-File -FilePath $path -Encoding UTF8
    return $path
}

# ================================================================
#  Main execution flow
# ================================================================

Write-Host ($ToolName + ' Windows Hardening Toolkit') -ForegroundColor Cyan
Show-Popup ($ToolName + ' is starting a security ' + $Mode + '.') ($ToolName + ' starting')

$elevated = Test-Admin
if (-not $elevated) {
    Write-Host 'Note: you are NOT running as Administrator.' -ForegroundColor Yellow
    Write-Host 'Audit will run, but some checks and all fixes need Administrator.' -ForegroundColor Yellow
}

if ($Mode -eq 'Apply') {
    if (-not $elevated) {
        Write-Host 'Apply mode needs Administrator. Re-open PowerShell as administrator and run again with -Mode Apply.' -ForegroundColor Red
        Show-Popup 'Apply mode needs Administrator. Re-run in an elevated PowerShell.' ($ToolName + ' stopped')
        return
    }

    $before = Invoke-Audit -Label 'BEFORE'

    Write-Host '=== Applying safe hardening fixes ===' -ForegroundColor Cyan
    $actions = Invoke-Apply
    foreach ($a in $actions) { Write-Host ('  ' + $a) -ForegroundColor Green }

    $after = Invoke-Audit -Label 'AFTER'

    $report = Write-Report -Summaries @($before, $after) -Actions $actions
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' apply complete.  Before ' + $before.Score + ' / 100,  After ' + $after.Score + ' / 100  (' + $after.Rating + ')') ($ToolName + ' complete')
}
else {
    $audit = Invoke-Audit

    $report = Write-Report -Summaries @($audit) -Actions @()
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' audit complete.  Score ' + $audit.Score + ' / 100  (' + $audit.Rating + ')') ($ToolName + ' complete')
}