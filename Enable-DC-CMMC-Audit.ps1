<#
.SYNOPSIS
    Enables the complete CMMC Level 2 (NIST SP 800-171 R2) Domain Controller audit
    baseline used by the Cyberlorians/CMMC guidance.

.DESCRIPTION
    Sets the 29 Advanced Audit Policy subcategories that generate every Security
    Event ID documented in DomainController_SecurityEvents_CMMC-L2_MDI.md, then
    enables the three settings that are NOT audit subcategories:
      * Force audit policy subcategory settings (SCENoApplyLegacyAuditPolicy)
      * Include command line in process creation events   -> Event 4688
      * Restrict NTLM: Audit NTLM authentication in this domain -> Events 8004 / 5168

    Subcategory GUIDs are universal across Windows locales, so this runs cleanly on
    any language build. auditpol /set is additive (it does NOT wipe other settings),
    unlike auditpol /restore.

.NOTES
    * Run on a Domain Controller from an ELEVATED PowerShell prompt.
    * Plain (non-CA) DC baseline. If the DC is also a Certificate Authority, uncomment
      the Certification Services line near the bottom.
    * Community resource - NOT official Microsoft guidance. Test before production.
#>

#requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# 1 = Success only | 3 = Success and Failure
$subcategories = @(
    # --- Account Logon ---
    @{ Name = 'Credential Validation';               Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Kerberos Authentication Service';     Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Kerberos Service Ticket Operations';  Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Value = 1 }
    # --- Account Management ---
    @{ Name = 'Computer Account Management';         Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Distribution Group Management';       Guid = '{0CCE9238-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Other Account Management Events';     Guid = '{0CCE923A-69AE-11D9-BED3-505054503030}'; Value = 1 }
    @{ Name = 'Security Group Management';           Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'User Account Management';             Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Value = 3 }
    # --- Detailed Tracking ---
    @{ Name = 'PNP Activity';                        Guid = '{0CCE9248-69AE-11D9-BED3-505054503030}'; Value = 1 }
    @{ Name = 'Process Creation';                    Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Value = 1 }
    # --- DS Access ---
    @{ Name = 'Directory Service Access';            Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Directory Service Changes';           Guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'; Value = 3 }
    # --- Logon/Logoff ---
    @{ Name = 'Account Lockout';                     Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Group Membership';                    Guid = '{0CCE9249-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Logoff';                              Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Logon';                               Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Other Logon/Logoff Events';           Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Special Logon';                       Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Value = 3 }
    # --- Object Access ---
    @{ Name = 'Removable Storage';                   Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Value = 3 }
    # --- Policy Change ---
    @{ Name = 'Audit Policy Change';                 Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Authentication Policy Change';        Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Authorization Policy Change';         Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'MPSSVC Rule-Level Policy Change';     Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Value = 3 }
    # --- Privilege Use ---
    @{ Name = 'Sensitive Privilege Use';             Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Value = 3 }
    # --- System ---
    @{ Name = 'IPsec Driver';                        Guid = '{0CCE9213-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Other System Events';                 Guid = '{0CCE9214-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Security State Change';               Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'Security System Extension';           Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Value = 3 }
    @{ Name = 'System Integrity';                    Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Value = 3 }

    # --- Certification Services (CA-only) --- uncomment ONLY if this DC is also a CA
    # @{ Name = 'Certification Services';            Guid = '{0CCE9221-69AE-11D9-BED3-505054503030}'; Value = 3 }
)

Write-Host "`n=== CMMC L2 Domain Controller audit baseline ===`n" -ForegroundColor Cyan
Write-Host ("Host: {0}   ({1} subcategories)`n" -f $env:COMPUTERNAME, $subcategories.Count)

$ok = 0; $fail = 0
foreach ($s in $subcategories) {
    $success = 'enable'
    $failure = if ($s.Value -eq 3) { 'enable' } else { 'disable' }
    $label   = if ($s.Value -eq 3) { 'Success+Failure' } else { 'Success' }

    & auditpol.exe /set /subcategory:"$($s.Guid)" /success:$success /failure:$failure | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ("  [OK]   {0,-40} {1}" -f $s.Name, $label) -ForegroundColor Green
        $ok++
    } else {
        Write-Host ("  [FAIL] {0,-40} (exit {1})" -f $s.Name, $LASTEXITCODE) -ForegroundColor Red
        $fail++
    }
}

Write-Host "`n--- Non-subcategory settings ---`n" -ForegroundColor Cyan

# Force audit policy subcategory settings to override legacy category settings
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' `
    -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "  [OK]   Force audit policy subcategory settings (SCENoApplyLegacyAuditPolicy=1)" -ForegroundColor Green

# Include command line in process creation events -> Event 4688
$audit = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $audit)) { New-Item -Path $audit -Force | Out-Null }
New-ItemProperty -Path $audit -Name 'ProcessCreationIncludeCmdLine_Enabled' `
    -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "  [OK]   Include command line in process creation events (4688)" -ForegroundColor Green

# Restrict NTLM: Audit NTLM authentication in this domain -> Events 8004 / 5168 (7 = enable all)
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters' `
    -Name 'AuditNTLMInDomain' -Value 7 -PropertyType DWord -Force | Out-Null
Write-Host "  [OK]   Restrict NTLM: Audit NTLM authentication in this domain (8004/5168)" -ForegroundColor Green

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host ("  Subcategories applied: {0}   Failed: {1}" -f $ok, $fail) -ForegroundColor $(if ($fail) { 'Yellow' } else { 'Green' })
Write-Host "`nVerify with:  auditpol /get /category:*`n"
