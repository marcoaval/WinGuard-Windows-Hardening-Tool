# WinGuard Windows Hardening Toolkit

WinGuard is a PowerShell security auditing and hardening tool I built for **IS2083 Advanced Scripting - Lab 2**. It checks a Windows 11 system against a set of Microsoft Security Baseline controls along with a few advanced hardening controls. It can audit the current settings, calculate a security score, write a report, and fix supported settings in Apply mode.

## What it does

- Runs in Audit mode for read-only security checks
- Runs in Apply mode to fix supported failed controls and then re-audit
- Groups results into Microsoft Security Baseline and Advanced hardening controls
- Shows PASS/FAIL results with the current setting values
- Calculates a weighted security score
- Saves timestamped text reports
- Shows start and completion pop-ups
- Attempts to create a System Restore Point before remediation

## Security controls

### Microsoft Security Baseline

- SMBv1 disabled
- SMB server signing required
- NTLM hardened with `LmCompatibilityLevel = 5`
- User Account Control enabled
- Minimum password length of at least 14
- Account lockout threshold from 1 to 10
- Windows Firewall enabled on Domain, Private, and Public profiles
- Microsoft Defender real-time protection enabled
- Guest account disabled
- Remote Desktop requires Network Level Authentication

### Advanced hardening

- Microsoft Defender PUA protection
- Attack Surface Reduction rule blocking Office applications from creating child processes
- PowerShell script block logging
- LSA protection with `RunAsPPL`
- BitLocker protection status on the system drive

BitLocker is audit only in the tool, so Apply mode does not turn it on automatically.

## Requirements

- Windows 11 Enterprise recommended for the full feature set
- Windows PowerShell 5.1 or PowerShell 7
- Administrator privileges for remediation
- Microsoft Defender, Firewall, SMB, and local account management cmdlets available

## How to run it

Open PowerShell as Administrator and change to the folder that contains the script.

If needed, allow local scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

If Windows marks the downloaded script as coming from the internet, unblock it once:

```powershell
Unblock-File .\Harden-Windows.ps1
```

### Audit mode

Audit mode is the default and does not intentionally change security settings:

```powershell
.\Harden-Windows.ps1
```

### Apply mode

Apply mode audits the system, attempts to create a restore point, remediates supported failed controls, and then runs another audit:

```powershell
.\Harden-Windows.ps1 -Mode Apply
```

Use Apply mode only on systems you own or are authorized to administer. I tested this project on a Windows 11 Enterprise evaluation VM.

## Reports

Reports are saved under:

```text
C:\Users\<username>\WinGuard_reports
```

Each report includes the control category, PASS/FAIL state, observed value, security score, and any remediation actions performed in Apply mode.

## Lab result

On my Windows 11 Enterprise test VM:

- Before hardening: **53 / 100 - NEEDS WORK**
- After hardening: **93 / 100 - STRONG**
- Microsoft Security Baseline after Apply: **10 / 10 passing**
- Advanced hardening after Apply: **4 / 5 passing**
- BitLocker remained off because that control is audit only

See `sample-before-after-report.txt` for a short example of the before and after results.

## Notes

- The `net accounts` checks assume an English-language Windows installation because the script looks for the labels `Minimum password length` and `Lockout threshold`.
- Some settings, especially LSA protection, can require a reboot before the protection is fully active.
- Defender settings can be affected by Tamper Protection or organizational policy.
- BitLocker availability and behavior can vary in virtual machines.

## AI assistance

AI assistance was used to explain PowerShell concepts, help draft some security checks, and troubleshoot errors during development. I reviewed and tested the implemented controls on the Windows 11 Enterprise lab VM before publishing the project.
