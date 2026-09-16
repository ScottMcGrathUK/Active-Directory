#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Get-ADSecurityAudit.ps1 - Read-only Active Directory security audit with a prioritised action plan.

.DESCRIPTION
    Runs a Tier 1 security audit against the current Active Directory domain and produces a
    prioritised, actionable report. Every check is READ-ONLY - the script never writes to the
    directory, changes a setting, or touches an account. It writes report files to disk only.

    Aimed at a small or immature domain where the depth of PingCastle or Purple Knight is more
    than is needed. It covers the findings that actually change risk, not a maturity score.

    Check groups:

    Domain baseline
        - Default domain password policy, built-in Guest account, krbtgt password age
        - ms-DS-MachineAccountQuota
        - Anonymous LDAP binds (dSHeuristics)
        - Pre-Windows 2000 Compatible Access membership

    Privileged access
        - Privileged group membership, nested groups, disabled members
        - Built-in Administrator (RID 500) usage and password age
        - Orphaned adminCount flags
        - Protected Users adoption and the "sensitive and cannot be delegated" flag
        - DCSync (directory replication) rights held by non-default principals
        - Dangerous ACEs on the domain root, AdminSDHolder and organisational units
        - Ownership of domain controller objects

    Delegation and Kerberos
        - Unconstrained, constrained and resource-based constrained delegation
        - Kerberoastable and AS-REP roastable accounts
        - Weak Kerberos encryption types (DES, RC4-only)

    Credential exposure
        - Group Policy Preferences cpassword in SYSVOL
        - Passwords left in the description and info attributes
        - Plaintext credentials in SYSVOL logon scripts
        - LAPS deployment coverage, not just schema presence
        - Password flags: never expires, reversible encryption, password not required

    Stale objects
        - Stale and never-logged-on user and computer accounts

    Domain controller hardening (remote registry, needs -SkipRemoteChecks if unavailable)
        - SMBv1, SMB signing, LDAP signing, LDAP channel binding
        - LmCompatibilityLevel, Print Spooler service, DSRM logon behaviour

    Recoverability
        - AD Recycle Bin, tombstone lifetime, last successful directory backup

    Output is written to a timestamped folder: an HTML report with an action plan, a plain text
    version of the same report for pasting into email or a document, Findings.csv, and one detail
    CSV per check that returned objects worth reviewing.

.PARAMETER OutputPath
    Folder under which the timestamped report folder is created. Defaults to the script's folder.

.PARAMETER StaleAccountDays
    Days without a logon before an enabled account is flagged as stale. Default 90.

.PARAMETER PrivilegedGroupWarnThreshold
    Membership count above which a privileged group is flagged. Default 5.

.PARAMETER KrbtgtMaxAgeDays
    Age in days above which the krbtgt password is flagged as due for rotation. Default 180.

.PARAMETER ServiceAccountPasswordMaxAgeDays
    Age in days above which a Kerberoastable service account password is treated as high risk.
    Default 365.

.PARAMETER NeverLoggedOnMinAgeDays
    Minimum age in days of an account that has never logged on before it is flagged, so freshly
    created accounts are not caught. Default 30. Lower this to test against a freshly seeded lab.

.PARAMETER SkipRemoteChecks
    Skip the per-domain-controller registry and service checks. Use when remote registry and
    WinRM are both unavailable, or when the account running the audit is not a domain admin.

.PARAMETER SkipSysvolScan
    Skip the SYSVOL file scan (GPP cpassword and logon script credentials). Use on a very large
    SYSVOL or over a slow link.

.NOTES
    DISCLAIMER - USE AT YOUR OWN RISK
    This script is provided "as is", without warranty of any kind, express or implied. The author
    accepts no liability for any loss, damage or disruption arising from its use. Although every
    check is designed to be read-only, you are responsible for reviewing the code and testing it
    in a non-production environment before running it against a live domain.

    The report files it produces contain sensitive information about your directory (account
    names, group membership, permissions, domain controller configuration and possible
    credentials found in attributes or SYSVOL). Store and share them accordingly.

    Run from a domain-joined Windows machine with the RSAT Active Directory tools installed.
    Windows PowerShell 5.1. Domain Admin (or equivalent read) rights avoid Access Denied gaps -
    ACL, SYSVOL and remote registry checks are the ones that suffer without them.

    Internal functions:
        _AddFinding                     _ExportDetail
        _GetRemoteRegistryValue         _ResolveMemberDetail
        _TestPasswordPolicy             _TestGuestAccount
        _TestKrbtgtAge                  _TestMachineAccountQuota
        _TestAnonymousLdapBinds         _TestPreWindows2000Access
        _TestPrivilegedGroups           _TestBuiltinAdministrator
        _TestAdminCountOrphans          _TestProtectedUsers
        _TestSensitiveAdminFlags        _TestDCSyncRights
        _TestDangerousAcls              _TestDomainControllerOwnership
        _TestUnconstrainedDelegation    _TestConstrainedDelegation
        _TestResourceBasedDelegation    _TestKerberoastableAccounts
        _TestAsRepRoastableAccounts     _TestWeakKerberosEncryption
        _TestGppPasswords               _TestPasswordsInAttributes
        _TestSysvolScriptCredentials    _TestLapsCoverage
        _TestPasswordFlags              _TestStaleAccounts
        _TestDomainControllerHardening  _TestRecycleBin
        _TestTombstoneLifetime          _TestBackupAge
        _WriteHtmlReport                _WriteTextReport

.EXAMPLE
    .\Get-ADSecurityAudit.ps1
    Runs the full audit against the current domain and writes the report next to the script.

.EXAMPLE
    .\Get-ADSecurityAudit.ps1 -OutputPath C:\Reports -SkipRemoteChecks
    Runs the audit without touching the domain controllers' registries, writing to C:\Reports.

.EXAMPLE
    .\Get-ADSecurityAudit.ps1 -StaleAccountDays 180 -PrivilegedGroupWarnThreshold 3
    Runs with a looser stale window and a stricter privileged group threshold.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
  Justification = 'This is an interactive report script. Progress lines and the closing summary are colour-coded status for a human at the console, not pipeline output - findings go to the HTML, TXT and CSV files.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
  Justification = 'Every parameter is consumed by the check functions defined below. PSScriptAnalyzer does not follow script-scope variables into functions declared in the same file.')]
[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$OutputPath = $PSScriptRoot,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 3650)]
  [int]$StaleAccountDays = 90,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 1000)]
  [int]$PrivilegedGroupWarnThreshold = 5,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 3650)]
  [int]$KrbtgtMaxAgeDays = 180,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 3650)]
  [int]$ServiceAccountPasswordMaxAgeDays = 365,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, 3650)]
  [int]$NeverLoggedOnMinAgeDays = 30,

  [Parameter(Mandatory = $false)]
  [switch]$SkipRemoteChecks,

  [Parameter(Mandatory = $false)]
  [switch]$SkipSysvolScan
)

#...................................
# Shared helpers
#...................................

function _AddFinding {
  <#
    Records one audit finding and echoes progress to the console.
    Status  - the outcome of the check.
    Severity - how much it matters if the status is Warn or Fail. Ignored for Pass.
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Deliberate colour-coded progress for the operator watching the run. The finding itself is recorded in $script:Findings and written to the report files.')]
  param(
    [Parameter(Mandatory = $true)][string]$Category,
    [Parameter(Mandatory = $true)][string]$Check,
    [Parameter(Mandatory = $true)][ValidateSet('Pass', 'Warn', 'Fail', 'Info', 'Error')][string]$Status,
    [Parameter(Mandatory = $true)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
    [Parameter(Mandatory = $true)][string]$Summary,
    [Parameter(Mandatory = $false)][string]$Remediation = '',
    [Parameter(Mandatory = $false)][string]$DetailFile = ''
  )

  $finding = [pscustomobject]@{
    Category    = $Category
    Check       = $Check
    Status      = $Status
    Severity    = $Severity
    Summary     = $Summary
    Remediation = $Remediation
    DetailFile  = $DetailFile
  }
  $script:Findings.Add($finding)

  $colour = switch ($Status) {
    'Pass'  { 'Green' }
    'Warn'  { 'Yellow' }
    'Fail'  { 'Red' }
    'Error' { 'Magenta' }
    default { 'Cyan' }
  }
  Write-Host ("[{0,-5}] {1} - {2}: {3}" -f $Status, $Category, $Check, $Summary) -ForegroundColor $colour
}

function _ExportDetail {
  <#
    Writes a detail CSV into the report folder and returns the file name, or an empty
    string when there was nothing to write.
  #>
  param(
    [Parameter(Mandatory = $false)]$InputObject,
    [Parameter(Mandatory = $true)][string]$FileName
  )

  if ($null -eq $InputObject) { return '' }
  $items = @($InputObject)
  if ($items.Count -eq 0) { return '' }

  try {
    $items | Export-Csv -Path (Join-Path $script:ReportFolder $FileName) -NoTypeInformation -Encoding UTF8
    return $FileName
  }
  catch {
    Write-Warning "Could not write $FileName : $($_.Exception.Message)"
    return ''
  }
}

function _GetRemoteRegistryValue {
  <#
    Reads a single HKLM registry value from a remote machine. Returns the value, $null when the
    key or value does not exist, or the sentinel string 'Unreachable' when the machine could not
    be contacted. Tries remote registry first, then falls back to WinRM.
  #>
  param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [Parameter(Mandatory = $true)][string]$SubKey,
    [Parameter(Mandatory = $true)][string]$ValueName
  )

  try {
    $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
    try {
      $key = $base.OpenSubKey($SubKey)
      if ($null -eq $key) { return $null }
      try { return $key.GetValue($ValueName) }
      finally { $key.Close() }
    }
    finally { $base.Close() }
  }
  catch {
    Write-Verbose "Remote registry failed for $ComputerName, trying WinRM: $($_.Exception.Message)"
  }

  try {
    $value = Invoke-Command -ComputerName $ComputerName -ErrorAction Stop -ScriptBlock {
      $remoteSubKey = $using:SubKey
      $remoteValue  = $using:ValueName
      $item = Get-ItemProperty -Path ("HKLM:\" + $remoteSubKey) -Name $remoteValue -ErrorAction SilentlyContinue
      if ($null -eq $item) { return $null }
      return $item.$remoteValue
    }
    return $value
  }
  catch {
    return 'Unreachable'
  }
}

function _ResolveMemberDetail {
  <#
    Turns a group member object into a flat record with the enabled state resolved.
    Never throws - unresolvable members come back with Unknown sentinels.
  #>
  param(
    [Parameter(Mandatory = $true)]$Member,
    [Parameter(Mandatory = $true)][string]$GroupName
  )

  $enabled       = 'Unknown'
  $lastLogon     = 'Unknown'
  $pwdLastSet    = 'Unknown'

  try {
    if ($Member.objectClass -eq 'user') {
      $u = Get-ADUser -Identity $Member.distinguishedName -Properties Enabled, LastLogonDate, PasswordLastSet -ErrorAction Stop
      $enabled    = $u.Enabled
      $lastLogon  = if ($u.LastLogonDate)   { $u.LastLogonDate }   else { 'Never' }
      $pwdLastSet = if ($u.PasswordLastSet) { $u.PasswordLastSet } else { 'Never' }
    }
    elseif ($Member.objectClass -eq 'computer') {
      $c = Get-ADComputer -Identity $Member.distinguishedName -Properties Enabled, LastLogonDate -ErrorAction Stop
      $enabled   = $c.Enabled
      $lastLogon = if ($c.LastLogonDate) { $c.LastLogonDate } else { 'Never' }
    }
  }
  catch {
    Write-Verbose "Could not resolve $($Member.distinguishedName): $($_.Exception.Message)"
  }

  [pscustomobject]@{
    Group             = $GroupName
    Name              = $Member.name
    SamAccountName    = $Member.SamAccountName
    ObjectClass       = $Member.objectClass
    Enabled           = $enabled
    LastLogon         = $lastLogon
    PasswordLastSet   = $pwdLastSet
    DistinguishedName = $Member.distinguishedName
  }
}

#...................................
# Domain baseline
#...................................

function _TestPasswordPolicy {
  Write-Verbose '..running function _TestPasswordPolicy'

  try {
    $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'Default Domain Password Policy' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the default domain password policy: $($_.Exception.Message)"
    return
  }

  if ($policy.MinPasswordLength -lt 14) {
    _AddFinding -Category 'Domain Baseline' -Check 'Minimum Password Length' -Status 'Warn' -Severity 'Medium' `
      -Summary "Minimum password length is $($policy.MinPasswordLength)." `
      -Remediation 'Raise the minimum to 14 or more in the Default Domain Policy. Pair it with a banned-password list rather than forced expiry.'
  }
  else {
    _AddFinding -Category 'Domain Baseline' -Check 'Minimum Password Length' -Status 'Pass' -Severity 'Info' `
      -Summary "Minimum password length is $($policy.MinPasswordLength)."
  }

  if (-not $policy.ComplexityEnabled) {
    _AddFinding -Category 'Domain Baseline' -Check 'Password Complexity' -Status 'Fail' -Severity 'High' `
      -Summary 'Password complexity is disabled for the domain.' `
      -Remediation 'Enable "Password must meet complexity requirements" in the Default Domain Policy.'
  }
  else {
    _AddFinding -Category 'Domain Baseline' -Check 'Password Complexity' -Status 'Pass' -Severity 'Info' `
      -Summary 'Password complexity is enabled.'
  }

  if ($policy.LockoutThreshold -eq 0) {
    _AddFinding -Category 'Domain Baseline' -Check 'Account Lockout Threshold' -Status 'Fail' -Severity 'High' `
      -Summary 'Account lockout is disabled (threshold 0), leaving every account open to password spraying.' `
      -Remediation 'Set a lockout threshold of 10 with a 15 minute window and 15 minute duration. That blunts spraying without creating a self-inflicted denial of service.'
  }
  else {
    _AddFinding -Category 'Domain Baseline' -Check 'Account Lockout Threshold' -Status 'Pass' -Severity 'Info' `
      -Summary "Account lockout threshold is $($policy.LockoutThreshold) attempts."
  }

  if ($policy.PasswordHistoryCount -lt 12) {
    _AddFinding -Category 'Domain Baseline' -Check 'Password History' -Status 'Warn' -Severity 'Low' `
      -Summary "Password history keeps $($policy.PasswordHistoryCount) password(s)." `
      -Remediation 'Set password history to 24 so users cannot cycle straight back to a known password.'
  }
  else {
    _AddFinding -Category 'Domain Baseline' -Check 'Password History' -Status 'Pass' -Severity 'Info' `
      -Summary "Password history keeps $($policy.PasswordHistoryCount) passwords."
  }

  try {
    $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop)
    if ($psos.Count -gt 0) {
      $detail = $psos | Select-Object Name, Precedence, MinPasswordLength, ComplexityEnabled, LockoutThreshold,
        @{ N = 'AppliesTo'; E = { ($_.AppliesTo -join '; ') } }
      $file = _ExportDetail -InputObject $detail -FileName 'FineGrainedPasswordPolicies.csv'
      $weak = @($psos | Where-Object { $_.MinPasswordLength -lt $policy.MinPasswordLength -or -not $_.ComplexityEnabled })
      if ($weak.Count -gt 0) {
        _AddFinding -Category 'Domain Baseline' -Check 'Fine-Grained Password Policies' -Status 'Warn' -Severity 'Medium' `
          -Summary "$($weak.Count) of $($psos.Count) fine-grained policy(ies) are weaker than the default domain policy." `
          -Remediation 'Review each PSO. A PSO that is weaker than the domain default is usually a forgotten exception for a service account.' `
          -DetailFile $file
      }
      else {
        _AddFinding -Category 'Domain Baseline' -Check 'Fine-Grained Password Policies' -Status 'Info' -Severity 'Info' `
          -Summary "$($psos.Count) fine-grained password policy(ies) in place, none weaker than the domain default." -DetailFile $file
      }
    }
    else {
      _AddFinding -Category 'Domain Baseline' -Check 'Fine-Grained Password Policies' -Status 'Info' -Severity 'Info' `
        -Summary 'No fine-grained password policies are defined.'
    }
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'Fine-Grained Password Policies' -Status 'Error' -Severity 'Info' `
      -Summary "Could not enumerate fine-grained password policies: $($_.Exception.Message)"
  }
}

function _TestGuestAccount {
  Write-Verbose '..running function _TestGuestAccount'

  try {
    $guest = Get-ADUser -Identity "$($script:Domain.DomainSID)-501" -Properties Enabled, Name -ErrorAction Stop
    if ($guest.Enabled) {
      _AddFinding -Category 'Domain Baseline' -Check 'Built-in Guest Account' -Status 'Fail' -Severity 'High' `
        -Summary "The built-in Guest account ($($guest.Name)) is enabled." `
        -Remediation 'Disable the Guest account. Nothing in a modern domain needs it.'
    }
    else {
      _AddFinding -Category 'Domain Baseline' -Check 'Built-in Guest Account' -Status 'Pass' -Severity 'Info' `
        -Summary 'The built-in Guest account is disabled.'
    }
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'Built-in Guest Account' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the Guest account: $($_.Exception.Message)"
  }
}

function _TestKrbtgtAge {
  Write-Verbose '..running function _TestKrbtgtAge'

  try {
    $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet -ErrorAction Stop
    if (-not $krbtgt.PasswordLastSet) {
      _AddFinding -Category 'Domain Baseline' -Check 'krbtgt Password Age' -Status 'Warn' -Severity 'High' `
        -Summary 'The krbtgt password has no PasswordLastSet value.' `
        -Remediation 'Rotate the krbtgt password twice, at least 10 hours apart, using the Microsoft krbtgt reset script.'
      return
    }

    $ageDays = [int](New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).TotalDays
    if ($ageDays -gt $KrbtgtMaxAgeDays) {
      $severity = if ($ageDays -gt ($KrbtgtMaxAgeDays * 2)) { 'High' } else { 'Medium' }
      _AddFinding -Category 'Domain Baseline' -Check 'krbtgt Password Age' -Status 'Warn' -Severity $severity `
        -Summary "The krbtgt password was last set $ageDays days ago (threshold $KrbtgtMaxAgeDays)." `
        -Remediation 'Rotate the krbtgt password twice, at least 10 hours apart (one full replication cycle plus ticket lifetime between resets). This invalidates any Golden Ticket forged from the current key.'
    }
    else {
      _AddFinding -Category 'Domain Baseline' -Check 'krbtgt Password Age' -Status 'Pass' -Severity 'Info' `
        -Summary "The krbtgt password was last set $ageDays days ago."
    }
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'krbtgt Password Age' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the krbtgt account: $($_.Exception.Message)"
  }
}

function _TestMachineAccountQuota {
  Write-Verbose '..running function _TestMachineAccountQuota'

  try {
    $quotaObject = Get-ADObject -Identity $script:Domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
    $quota = $quotaObject.'ms-DS-MachineAccountQuota'
    if ($null -eq $quota) { $quota = 10 }

    if ($quota -gt 0) {
      _AddFinding -Category 'Domain Baseline' -Check 'ms-DS-MachineAccountQuota' -Status 'Fail' -Severity 'High' `
        -Summary "Any authenticated user can join $quota computer(s) to the domain." `
        -Remediation 'Set ms-DS-MachineAccountQuota to 0 on the domain object and delegate machine join rights to the helpdesk group instead. A non-zero quota is the first step in most resource-based constrained delegation attacks.'
    }
    else {
      _AddFinding -Category 'Domain Baseline' -Check 'ms-DS-MachineAccountQuota' -Status 'Pass' -Severity 'Info' `
        -Summary 'ms-DS-MachineAccountQuota is 0. Ordinary users cannot join machines.'
    }
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'ms-DS-MachineAccountQuota' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read ms-DS-MachineAccountQuota: $($_.Exception.Message)"
  }
}

function _TestAnonymousLdapBinds {
  Write-Verbose '..running function _TestAnonymousLdapBinds'

  try {
    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,$($script:ConfigNC)"
    $ds = Get-ADObject -Identity $dsPath -Properties dSHeuristics -ErrorAction Stop
    $heuristics = $ds.dSHeuristics

    if ([string]::IsNullOrEmpty($heuristics)) {
      _AddFinding -Category 'Domain Baseline' -Check 'Anonymous LDAP Binds' -Status 'Pass' -Severity 'Info' `
        -Summary 'dSHeuristics is not set, so anonymous LDAP operations are not permitted.'
      return
    }

    $seventh = if ($heuristics.Length -ge 7) { $heuristics.Substring(6, 1) } else { '0' }
    if ($seventh -eq '2') {
      _AddFinding -Category 'Domain Baseline' -Check 'Anonymous LDAP Binds' -Status 'Fail' -Severity 'High' `
        -Summary "dSHeuristics is '$heuristics'. The 7th character is 2, which permits anonymous LDAP operations." `
        -Remediation 'Clear the 7th character of dSHeuristics back to 0. Anonymous LDAP lets an unauthenticated attacker enumerate the entire directory.'
    }
    else {
      _AddFinding -Category 'Domain Baseline' -Check 'Anonymous LDAP Binds' -Status 'Pass' -Severity 'Info' `
        -Summary "dSHeuristics is '$heuristics'. Anonymous LDAP operations are not permitted."
    }
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'Anonymous LDAP Binds' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read dSHeuristics: $($_.Exception.Message)"
  }
}

function _TestPreWindows2000Access {
  Write-Verbose '..running function _TestPreWindows2000Access'

  try {
    $group = Get-ADGroup -Identity 'S-1-5-32-554' -Properties member -ErrorAction Stop
    $members = @($group.member)
    $risky = @($members | Where-Object { $_ -match 'CN=S-1-1-0|CN=S-1-5-7|CN=S-1-5-11' })

    if ($risky.Count -gt 0) {
      $detail = $risky | ForEach-Object { [pscustomobject]@{ Group = $group.Name; MemberDN = $_ } }
      $file = _ExportDetail -InputObject $detail -FileName 'PreWindows2000Access.csv'
      _AddFinding -Category 'Domain Baseline' -Check 'Pre-Windows 2000 Compatible Access' -Status 'Fail' -Severity 'High' `
        -Summary "The Pre-Windows 2000 Compatible Access group contains $($risky.Count) broad principal(s) such as Everyone or Anonymous Logon." `
        -Remediation 'Remove Everyone, Anonymous Logon and Authenticated Users from Pre-Windows 2000 Compatible Access. It grants directory read to anyone who can reach a domain controller.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Domain Baseline' -Check 'Pre-Windows 2000 Compatible Access' -Status 'Pass' -Severity 'Info' `
        -Summary "The group has $($members.Count) member(s), none of them broad well-known principals."
    }
  }
  catch {
    _AddFinding -Category 'Domain Baseline' -Check 'Pre-Windows 2000 Compatible Access' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the Pre-Windows 2000 Compatible Access group: $($_.Exception.Message)"
  }
}

#...................................
# Privileged access
#...................................

function _TestPrivilegedGroups {
  Write-Verbose '..running function _TestPrivilegedGroups'

  $groupNames = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators',
    'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners',
    'Key Admins', 'Enterprise Key Admins'
  )

  $allMembers  = New-Object System.Collections.Generic.List[pscustomobject]
  $nestedGroups = New-Object System.Collections.Generic.List[pscustomobject]

  foreach ($groupName in $groupNames) {
    $group = $null
    try { $group = Get-ADGroup -Identity $groupName -ErrorAction Stop }
    catch {
      # Enterprise Admins, Schema Admins and the Key Admins groups only exist in the forest root.
      # DnsAdmins only exists where DNS is AD-integrated. A missing group is not a finding.
      Write-Verbose "Group $groupName does not exist in this domain, skipping."
      continue
    }

    try {
      $direct = @(Get-ADGroupMember -Identity $group -ErrorAction Stop)
      $recursive = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop)
    }
    catch {
      _AddFinding -Category 'Privileged Access' -Check "$groupName Membership" -Status 'Error' -Severity 'Info' `
        -Summary "Could not enumerate members of $groupName : $($_.Exception.Message)"
      continue
    }

    foreach ($member in $recursive) {
      $allMembers.Add((_ResolveMemberDetail -Member $member -GroupName $groupName))
    }

    foreach ($d in ($direct | Where-Object { $_.objectClass -eq 'group' })) {
      $nestedGroups.Add([pscustomobject]@{
        PrivilegedGroup   = $groupName
        NestedGroup       = $d.name
        DistinguishedName = $d.distinguishedName
      })
    }

    $count = $recursive.Count
    if ($groupName -eq 'Schema Admins') {
      if ($count -gt 0) {
        _AddFinding -Category 'Privileged Access' -Check 'Schema Admins Membership' -Status 'Warn' -Severity 'Medium' `
          -Summary "Schema Admins has $count member(s)." `
          -Remediation 'Schema Admins should be empty except during a schema change. Remove the members and add one back temporarily when a schema extension is actually being applied.' `
          -DetailFile 'PrivilegedGroupMembers.csv'
      }
      else {
        _AddFinding -Category 'Privileged Access' -Check 'Schema Admins Membership' -Status 'Pass' -Severity 'Info' `
          -Summary 'Schema Admins is empty, which is correct outside a schema change.'
      }
      continue
    }

    if ($count -gt $PrivilegedGroupWarnThreshold) {
      $severity = if ($groupName -in @('Domain Admins', 'Enterprise Admins', 'Administrators')) { 'High' } else { 'Medium' }
      _AddFinding -Category 'Privileged Access' -Check "$groupName Membership" -Status 'Warn' -Severity $severity `
        -Summary "$count effective member(s), above the threshold of $PrivilegedGroupWarnThreshold." `
        -Remediation "Review every member of $groupName. Each one should be a named, dedicated admin account with no mailbox and no day-to-day use. Move anything that only needs a subset of rights to a delegated group." `
        -DetailFile 'PrivilegedGroupMembers.csv'
    }
    elseif ($count -eq 0) {
      _AddFinding -Category 'Privileged Access' -Check "$groupName Membership" -Status 'Pass' -Severity 'Info' `
        -Summary "$groupName is empty."
    }
    else {
      _AddFinding -Category 'Privileged Access' -Check "$groupName Membership" -Status 'Pass' -Severity 'Info' `
        -Summary "$count effective member(s)."
    }
  }

  $script:PrivilegedMembers = $allMembers
  [void](_ExportDetail -InputObject $allMembers -FileName 'PrivilegedGroupMembers.csv')

  if ($nestedGroups.Count -gt 0) {
    $file = _ExportDetail -InputObject $nestedGroups -FileName 'NestedPrivilegedGroups.csv'
    _AddFinding -Category 'Privileged Access' -Check 'Nested Groups in Privileged Groups' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($nestedGroups.Count) group(s) are nested directly inside a privileged group, which hides the real membership." `
      -Remediation 'Flatten the nesting. Privileged groups should contain named user accounts only, so that "who is a Domain Admin" is answerable at a glance.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Nested Groups in Privileged Groups' -Status 'Pass' -Severity 'Info' `
      -Summary 'No groups are nested inside the privileged groups.'
  }

  $disabled = @($allMembers | Where-Object { $_.Enabled -eq $false })
  if ($disabled.Count -gt 0) {
    $file = _ExportDetail -InputObject $disabled -FileName 'DisabledPrivilegedAccounts.csv'
    _AddFinding -Category 'Privileged Access' -Check 'Disabled Accounts in Privileged Groups' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($disabled.Count) disabled account(s) are still members of privileged groups." `
      -Remediation 'Remove disabled accounts from privileged groups. A disabled account that is later re-enabled by a helpdesk request silently comes back as an admin.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Disabled Accounts in Privileged Groups' -Status 'Pass' -Severity 'Info' `
      -Summary 'No disabled accounts are in privileged groups.'
  }

  $cutoff = (Get-Date).AddDays(-$StaleAccountDays)
  $staleAdmins = @($allMembers | Where-Object {
    $_.ObjectClass -eq 'user' -and $_.Enabled -eq $true -and
    ($_.LastLogon -eq 'Never' -or ($_.LastLogon -is [datetime] -and $_.LastLogon -lt $cutoff))
  })
  if ($staleAdmins.Count -gt 0) {
    $file = _ExportDetail -InputObject $staleAdmins -FileName 'StalePrivilegedAccounts.csv'
    _AddFinding -Category 'Privileged Access' -Check 'Unused Privileged Accounts' -Status 'Warn' -Severity 'High' `
      -Summary "$($staleAdmins.Count) enabled privileged account(s) have not logged on in $StaleAccountDays days." `
      -Remediation 'An admin account nobody uses is an admin account nobody notices being used. Disable it, or remove the privileged group membership and leave the account for normal work.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Unused Privileged Accounts' -Status 'Pass' -Severity 'Info' `
      -Summary 'All enabled privileged accounts have logged on recently.'
  }
}

function _TestBuiltinAdministrator {
  Write-Verbose '..running function _TestBuiltinAdministrator'

  try {
    $admin = Get-ADUser -Identity "$($script:Domain.DomainSID)-500" `
      -Properties Name, SamAccountName, Enabled, PasswordLastSet, LastLogonDate, ServicePrincipalName -ErrorAction Stop
  }
  catch {
    _AddFinding -Category 'Privileged Access' -Check 'Built-in Administrator (RID 500)' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the built-in Administrator account: $($_.Exception.Message)"
    return
  }

  $pwdAge = 'Unknown'
  if ($admin.PasswordLastSet) {
    $pwdAge = [int](New-TimeSpan -Start $admin.PasswordLastSet -End (Get-Date)).TotalDays
  }

  $lastLogon = if ($admin.LastLogonDate) { $admin.LastLogonDate.ToString('yyyy-MM-dd') } else { 'never' }
  $detail = [pscustomobject]@{
    Name            = $admin.Name
    SamAccountName  = $admin.SamAccountName
    Enabled         = $admin.Enabled
    PasswordAgeDays = $pwdAge
    LastLogon       = $lastLogon
    Renamed         = ($admin.SamAccountName -ne 'Administrator')
  }
  $file = _ExportDetail -InputObject $detail -FileName 'BuiltinAdministrator.csv'

  if ($pwdAge -is [int] -and $pwdAge -gt 365) {
    _AddFinding -Category 'Privileged Access' -Check 'Built-in Administrator (RID 500)' -Status 'Warn' -Severity 'High' `
      -Summary "The built-in Administrator password is $pwdAge days old. Last logon: $lastLogon." `
      -Remediation 'Rotate the built-in Administrator password and store it in a break-glass vault. It is the one account that cannot be locked out, so its password age matters more than any other.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Built-in Administrator (RID 500)' -Status 'Pass' -Severity 'Info' `
      -Summary "Password age $pwdAge day(s), last logon $lastLogon." -DetailFile $file
  }

  if ($admin.SamAccountName -eq 'Administrator') {
    _AddFinding -Category 'Privileged Access' -Check 'Built-in Administrator Name' -Status 'Info' -Severity 'Low' `
      -Summary 'The built-in Administrator account still uses its default name.' `
      -Remediation 'Renaming it is cosmetic, since the RID 500 SID is what attackers target. Worth doing only alongside a decoy account, and low priority either way.'
  }
}

function _TestAdminCountOrphans {
  Write-Verbose '..running function _TestAdminCountOrphans'

  $currentPrivileged = @($script:PrivilegedMembers | Select-Object -ExpandProperty SamAccountName -Unique)

  try {
    $flagged = @(Get-ADObject -LDAPFilter '(&(adminCount=1)(|(objectClass=user)(objectClass=group)))' `
      -Properties SamAccountName, objectClass, whenChanged -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Privileged Access' -Check 'Orphaned adminCount Flags' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query adminCount: $($_.Exception.Message)"
    return
  }

  $orphans = @($flagged | Where-Object {
    $_.objectClass -eq 'user' -and $_.SamAccountName -and $_.SamAccountName -notin $currentPrivileged
  })

  if ($orphans.Count -gt 0) {
    $detail = $orphans | Select-Object Name, SamAccountName, whenChanged, DistinguishedName
    $file = _ExportDetail -InputObject $detail -FileName 'AdminCountOrphans.csv'
    _AddFinding -Category 'Privileged Access' -Check 'Orphaned adminCount Flags' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($orphans.Count) account(s) carry adminCount=1 but are no longer in any privileged group." `
      -Remediation 'These accounts were privileged in the past and still have AdminSDHolder-inherited permissions and broken inheritance. Clear adminCount and re-enable inheritance on each, after confirming they should not be privileged.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Orphaned adminCount Flags' -Status 'Pass' -Severity 'Info' `
      -Summary 'No orphaned adminCount flags found.'
  }
}

function _TestProtectedUsers {
  Write-Verbose '..running function _TestProtectedUsers'

  try {
    $protected = @(Get-ADGroupMember -Identity "$($script:Domain.DomainSID)-525" -Recursive -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Privileged Access' -Check 'Protected Users Adoption' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the Protected Users group: $($_.Exception.Message)"
    return
  }

  $protectedSams = @($protected | Select-Object -ExpandProperty SamAccountName)
  $adminUsers = @($script:PrivilegedMembers | Where-Object { $_.ObjectClass -eq 'user' -and $_.Enabled -eq $true } |
    Sort-Object -Property SamAccountName -Unique | Select-Object -Property Name, SamAccountName, Group, LastLogon)
  $missing = @($adminUsers | Where-Object { $_.SamAccountName -notin $protectedSams })

  if ($protected.Count -eq 0) {
    _AddFinding -Category 'Privileged Access' -Check 'Protected Users Adoption' -Status 'Warn' -Severity 'Medium' `
      -Summary "Protected Users is empty while $($adminUsers.Count) enabled privileged account(s) exist." `
      -Remediation 'Add tier-0 admin accounts to Protected Users. It forces AES Kerberos, blocks NTLM, blocks delegation and stops credential caching for those accounts. Test with one account first - it breaks anything relying on NTLM or unconstrained delegation.' `
      -DetailFile (_ExportDetail -InputObject $adminUsers -FileName 'ProtectedUsersCandidates.csv')
  }
  elseif ($missing.Count -gt 0) {
    _AddFinding -Category 'Privileged Access' -Check 'Protected Users Adoption' -Status 'Warn' -Severity 'Low' `
      -Summary "$($protected.Count) account(s) are in Protected Users, but $($missing.Count) enabled privileged account(s) are not." `
      -Remediation 'Extend Protected Users membership to the remaining tier-0 admin accounts once each has been tested.' `
      -DetailFile (_ExportDetail -InputObject $missing -FileName 'ProtectedUsersCandidates.csv')
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Protected Users Adoption' -Status 'Pass' -Severity 'Info' `
      -Summary "All $($adminUsers.Count) enabled privileged account(s) are in Protected Users."
  }
}

function _TestSensitiveAdminFlags {
  Write-Verbose '..running function _TestSensitiveAdminFlags'

  try {
    $notDelegated = @(Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=1048576)' -ErrorAction Stop |
      Select-Object -ExpandProperty SamAccountName)
  }
  catch {
    _AddFinding -Category 'Privileged Access' -Check 'Sensitive And Cannot Be Delegated' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query the NOT_DELEGATED flag: $($_.Exception.Message)"
    return
  }

  $adminUsers = @($script:PrivilegedMembers | Where-Object { $_.ObjectClass -eq 'user' -and $_.Enabled -eq $true } |
    Sort-Object -Property SamAccountName -Unique | Select-Object -Property Name, SamAccountName, Group, LastLogon)
  $missing = @($adminUsers | Where-Object { $_.SamAccountName -notin $notDelegated })

  if ($missing.Count -gt 0) {
    $file = _ExportDetail -InputObject $missing -FileName 'AdminsWithoutSensitiveFlag.csv'
    _AddFinding -Category 'Privileged Access' -Check 'Sensitive And Cannot Be Delegated' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($missing.Count) of $($adminUsers.Count) enabled privileged account(s) lack the 'sensitive and cannot be delegated' flag." `
      -Remediation 'Set the flag on every tier-0 admin account, or add them to Protected Users which implies it. Without it, a compromised server trusted for delegation can impersonate an admin who authenticated to it.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Sensitive And Cannot Be Delegated' -Status 'Pass' -Severity 'Info' `
      -Summary 'All enabled privileged accounts are marked as sensitive and cannot be delegated.'
  }
}

function _TestDCSyncRights {
  Write-Verbose '..running function _TestDCSyncRights'

  # Extended right GUIDs for directory replication. Holding the first two together is DCSync.
  $replGuids = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
  }

  # Principals that hold these rights by design in a healthy domain.
  $expected = @(
    'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM', 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
    "$($script:Domain.NetBIOSName)\Domain Controllers", "$($script:Domain.NetBIOSName)\Domain Admins",
    "$($script:Domain.NetBIOSName)\Enterprise Admins", "$($script:Domain.NetBIOSName)\Enterprise Read-only Domain Controllers"
  )

  try {
    $acl = Get-Acl -Path "AD:\$($script:Domain.DistinguishedName)" -ErrorAction Stop
  }
  catch {
    _AddFinding -Category 'Privileged Access' -Check 'DCSync Rights' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the ACL on the domain root: $($_.Exception.Message)"
    return
  }

  $holders = New-Object System.Collections.Generic.List[pscustomobject]
  foreach ($ace in $acl.Access) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    $guid = $ace.ObjectType.ToString()
    if (-not $replGuids.ContainsKey($guid)) { continue }

    $identity = $ace.IdentityReference.Value
    $holders.Add([pscustomobject]@{
      Identity    = $identity
      Right       = $replGuids[$guid]
      Inherited   = $ace.IsInherited
      ExpectedHolder = ($identity -in $expected)
    })
  }

  $unexpected = @($holders | Where-Object { -not $_.ExpectedHolder })
  [void](_ExportDetail -InputObject $holders -FileName 'DCSyncRightsHolders.csv')

  if ($unexpected.Count -gt 0) {
    $names = @($unexpected | Select-Object -ExpandProperty Identity -Unique)
    _AddFinding -Category 'Privileged Access' -Check 'DCSync Rights' -Status 'Fail' -Severity 'High' `
      -Summary "$($names.Count) non-default principal(s) hold directory replication rights on the domain root: $($names -join ', ')." `
      -Remediation 'Anything holding Get-Changes and Get-Changes-All can pull every password hash in the domain, including krbtgt. Entra Connect and some backup agents legitimately need this - confirm each one, and remove the rest.' `
      -DetailFile 'DCSyncRightsHolders.csv'
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'DCSync Rights' -Status 'Pass' -Severity 'Info' `
      -Summary 'Only the expected default principals hold directory replication rights.' `
      -DetailFile 'DCSyncRightsHolders.csv'
  }
}

function _TestDangerousAcls {
  Write-Verbose '..running function _TestDangerousAcls'

  # Broad principals that should never hold write-class rights on a container.
  $broadPrincipals = @(
    'Everyone', 'NT AUTHORITY\Authenticated Users', 'NT AUTHORITY\ANONYMOUS LOGON', 'NT AUTHORITY\INTERACTIVE',
    "$($script:Domain.NetBIOSName)\Domain Users", "$($script:Domain.NetBIOSName)\Domain Computers",
    "$($script:Domain.NetBIOSName)\Domain Guests", 'BUILTIN\Users', 'BUILTIN\Guests'
  )
  $dangerousRights = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|CreateChild|DeleteChild|ExtendedRight|Self'

  $targets = New-Object System.Collections.Generic.List[pscustomobject]
  $targets.Add([pscustomobject]@{ Label = 'Domain root'; DN = $script:Domain.DistinguishedName })
  $targets.Add([pscustomobject]@{ Label = 'AdminSDHolder'; DN = "CN=AdminSDHolder,CN=System,$($script:Domain.DistinguishedName)" })
  $targets.Add([pscustomobject]@{ Label = 'Domain Controllers OU'; DN = $script:Domain.DomainControllersContainer })

  try {
    foreach ($ou in (Get-ADOrganizationalUnit -Filter * -ErrorAction Stop)) {
      if ($ou.DistinguishedName -eq $script:Domain.DomainControllersContainer) { continue }
      $targets.Add([pscustomobject]@{ Label = "OU: $($ou.Name)"; DN = $ou.DistinguishedName })
    }
  }
  catch {
    Write-Verbose "Could not enumerate OUs: $($_.Exception.Message)"
  }

  $findings = New-Object System.Collections.Generic.List[pscustomobject]
  foreach ($target in $targets) {
    try {
      $acl = Get-Acl -Path "AD:\$($target.DN)" -ErrorAction Stop
    }
    catch {
      $findings.Add([pscustomobject]@{
        Object = $target.Label; Identity = 'Unknown'; Rights = 'Error'
        Inherited = 'Unknown'; DistinguishedName = $target.DN
      })
      continue
    }

    foreach ($ace in $acl.Access) {
      if ($ace.AccessControlType -ne 'Allow') { continue }
      if ($ace.IdentityReference.Value -notin $broadPrincipals) { continue }
      if ($ace.ActiveDirectoryRights.ToString() -notmatch $dangerousRights) { continue }

      $findings.Add([pscustomobject]@{
        Object            = $target.Label
        Identity          = $ace.IdentityReference.Value
        Rights            = $ace.ActiveDirectoryRights.ToString()
        Inherited         = $ace.IsInherited
        DistinguishedName = $target.DN
      })
    }
  }

  if ($findings.Count -gt 0) {
    $file = _ExportDetail -InputObject $findings -FileName 'DangerousAcls.csv'
    $criticalObjects = @($findings | Where-Object { $_.Object -in @('Domain root', 'AdminSDHolder', 'Domain Controllers OU') })
    $severity = if ($criticalObjects.Count -gt 0) { 'High' } else { 'Medium' }
    _AddFinding -Category 'Privileged Access' -Check 'Dangerous ACEs on Containers' -Status 'Fail' -Severity $severity `
      -Summary "$($findings.Count) write-class permission(s) held by broad principals such as Authenticated Users or Domain Users across $(@($findings | Select-Object -ExpandProperty Object -Unique).Count) container(s)." `
      -Remediation 'Review each entry. A broad principal with GenericAll, WriteDacl or WriteProperty on an OU or on the domain root is a direct path to privilege escalation. Replace with a delegated group scoped to the specific task.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Dangerous ACEs on Containers' -Status 'Pass' -Severity 'Info' `
      -Summary "No broad principals hold write-class rights across $($targets.Count) container(s) checked."
  }
}

function _TestDomainControllerOwnership {
  Write-Verbose '..running function _TestDomainControllerOwnership'

  $acceptableOwners = @(
    'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM',
    "$($script:Domain.NetBIOSName)\Domain Admins", "$($script:Domain.NetBIOSName)\Enterprise Admins"
  )

  $results = New-Object System.Collections.Generic.List[pscustomobject]
  foreach ($dc in $script:AllDCs) {
    $owner = 'Unknown'
    try { $owner = (Get-Acl -Path "AD:\$($dc.ComputerObjectDN)" -ErrorAction Stop).Owner }
    catch { $owner = 'Error' }

    $results.Add([pscustomobject]@{
      DomainController = $dc.HostName
      Owner            = $owner
      Acceptable       = ($owner -in $acceptableOwners)
    })
  }

  $bad = @($results | Where-Object { -not $_.Acceptable })
  if ($bad.Count -gt 0) {
    $file = _ExportDetail -InputObject $results -FileName 'DomainControllerOwnership.csv'
    _AddFinding -Category 'Privileged Access' -Check 'Domain Controller Object Ownership' -Status 'Warn' -Severity 'High' `
      -Summary "$($bad.Count) domain controller object(s) are not owned by an expected tier-0 principal." `
      -Remediation 'Ownership overrides permissions - an owner can always rewrite the ACL. Reset the owner of each DC computer object to Domain Admins.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Privileged Access' -Check 'Domain Controller Object Ownership' -Status 'Pass' -Severity 'Info' `
      -Summary "All $($results.Count) domain controller object(s) are owned by a tier-0 principal."
  }
}

#...................................
# Delegation and Kerberos
#...................................

function _TestUnconstrainedDelegation {
  Write-Verbose '..running function _TestUnconstrainedDelegation'

  try {
    $objects = @(Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
      -Properties samAccountName, objectClass, primaryGroupID -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Unconstrained Delegation' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query unconstrained delegation: $($_.Exception.Message)"
    return
  }

  # primaryGroupID 516 and 521 are domain controllers and RODCs, which hold this flag by design.
  $offenders = @($objects | Where-Object { $_.primaryGroupID -notin 516, 521 })

  if ($offenders.Count -gt 0) {
    $detail = $offenders | Select-Object Name, samAccountName, objectClass, DistinguishedName
    $file = _ExportDetail -InputObject $detail -FileName 'UnconstrainedDelegation.csv'
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Unconstrained Delegation' -Status 'Fail' -Severity 'High' `
      -Summary "$($offenders.Count) non-domain-controller object(s) are trusted for unconstrained delegation." `
      -Remediation 'Any admin who authenticates to one of these hosts leaves a usable TGT in its memory. Convert each to constrained or resource-based constrained delegation, and until then add your admin accounts to Protected Users.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Unconstrained Delegation' -Status 'Pass' -Severity 'Info' `
      -Summary 'Only domain controllers are trusted for unconstrained delegation.'
  }
}

function _TestConstrainedDelegation {
  Write-Verbose '..running function _TestConstrainedDelegation'

  try {
    $objects = @(Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' `
      -Properties samAccountName, objectClass, 'msDS-AllowedToDelegateTo', userAccountControl -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Constrained Delegation' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query constrained delegation: $($_.Exception.Message)"
    return
  }

  if ($objects.Count -eq 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Constrained Delegation' -Status 'Pass' -Severity 'Info' `
      -Summary 'No objects are configured for constrained delegation.'
    return
  }

  $detail = $objects | ForEach-Object {
    # 0x1000000 TRUSTED_TO_AUTH_FOR_DELEGATION marks protocol transition (any authentication protocol).
    $protocolTransition = (($_.userAccountControl -band 16777216) -ne 0)
    [pscustomobject]@{
      Name               = $_.Name
      SamAccountName     = $_.samAccountName
      ObjectClass        = $_.objectClass
      ProtocolTransition = $protocolTransition
      DelegatesTo        = ($_.'msDS-AllowedToDelegateTo' -join '; ')
      DistinguishedName  = $_.DistinguishedName
    }
  }
  $file = _ExportDetail -InputObject $detail -FileName 'ConstrainedDelegation.csv'

  $withTransition = @($detail | Where-Object { $_.ProtocolTransition })
  if ($withTransition.Count -gt 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Constrained Delegation' -Status 'Fail' -Severity 'High' `
      -Summary "$($objects.Count) object(s) use constrained delegation, $($withTransition.Count) of them with protocol transition." `
      -Remediation 'Protocol transition lets the host request a ticket for any user without that user ever authenticating to it. Remove "use any authentication protocol" where the service does not genuinely need it, and check the target SPNs are not on a domain controller.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Constrained Delegation' -Status 'Warn' -Severity 'Low' `
      -Summary "$($objects.Count) object(s) use constrained delegation (Kerberos only, no protocol transition)." `
      -Remediation 'Confirm each delegation is still required and that no target SPN belongs to a domain controller or other tier-0 host.' `
      -DetailFile $file
  }
}

function _TestResourceBasedDelegation {
  Write-Verbose '..running function _TestResourceBasedDelegation'

  try {
    $objects = @(Get-ADObject -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
      -Properties samAccountName, objectClass, 'msDS-AllowedToActOnBehalfOfOtherIdentity' -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Resource-Based Constrained Delegation' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query resource-based constrained delegation: $($_.Exception.Message)"
    return
  }

  if ($objects.Count -eq 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Resource-Based Constrained Delegation' -Status 'Pass' -Severity 'Info' `
      -Summary 'No objects have msDS-AllowedToActOnBehalfOfOtherIdentity set.'
    return
  }

  $detail = $objects | ForEach-Object {
    $allowed = 'Unknown'
    try {
      $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
      $sd.SetSecurityDescriptorBinaryForm($_.'msDS-AllowedToActOnBehalfOfOtherIdentity')
      $allowed = (($sd.Access | Select-Object -ExpandProperty IdentityReference | Select-Object -Unique) -join '; ')
    }
    catch {
      $allowed = 'Could not parse security descriptor'
    }

    [pscustomobject]@{
      Name              = $_.Name
      SamAccountName    = $_.samAccountName
      ObjectClass       = $_.objectClass
      AllowedToActAs    = $allowed
      DistinguishedName = $_.DistinguishedName
    }
  }
  $file = _ExportDetail -InputObject $detail -FileName 'ResourceBasedDelegation.csv'

  _AddFinding -Category 'Delegation and Kerberos' -Check 'Resource-Based Constrained Delegation' -Status 'Warn' -Severity 'High' `
    -Summary "$($objects.Count) object(s) allow another principal to act on their behalf." `
    -Remediation 'RBCD is the usual payload of a machine-account takeover. Confirm every entry was configured deliberately, and cross-check against ms-DS-MachineAccountQuota being 0.' `
    -DetailFile $file
}

function _TestKerberoastableAccounts {
  Write-Verbose '..running function _TestKerberoastableAccounts'

  try {
    $spnUsers = @(Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(samAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
      -Properties ServicePrincipalName, PasswordLastSet, adminCount, 'msDS-SupportedEncryptionTypes', LastLogonDate -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Kerberoastable Accounts' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query accounts with SPNs: $($_.Exception.Message)"
    return
  }

  if ($spnUsers.Count -eq 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Kerberoastable Accounts' -Status 'Pass' -Severity 'Info' `
      -Summary 'No enabled user accounts have a service principal name set.'
    return
  }

  $detail = $spnUsers | ForEach-Object {
    $ageDays = 'Never set'
    if ($_.PasswordLastSet) { $ageDays = [int](New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).TotalDays }

    $encTypes = $_.'msDS-SupportedEncryptionTypes'
    $aesSupported = 'No (defaults to RC4)'
    if ($null -ne $encTypes -and ($encTypes -band 24) -ne 0) { $aesSupported = 'Yes' }

    [pscustomobject]@{
      Name                = $_.Name
      SamAccountName      = $_.SamAccountName
      Privileged          = ($_.adminCount -eq 1)
      PasswordAgeDays     = $ageDays
      AesSupported        = $aesSupported
      LastLogon           = $(if ($_.LastLogonDate) { $_.LastLogonDate } else { 'Never' })
      ServicePrincipalNames = ($_.ServicePrincipalName -join '; ')
    }
  }
  $file = _ExportDetail -InputObject $detail -FileName 'KerberoastableAccounts.csv'

  $privileged = @($detail | Where-Object { $_.Privileged })
  $oldPasswords = @($detail | Where-Object { $_.PasswordAgeDays -is [int] -and $_.PasswordAgeDays -gt $ServiceAccountPasswordMaxAgeDays })

  if ($privileged.Count -gt 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Kerberoastable Accounts' -Status 'Fail' -Severity 'High' `
      -Summary "$($privileged.Count) privileged account(s) have an SPN and are Kerberoastable, out of $($spnUsers.Count) SPN account(s) in total." `
      -Remediation 'A privileged account with an SPN hands an attacker an offline crack straight to Domain Admin. Remove the SPN, or move the service to a group managed service account. Where neither is possible, set a 25+ character random password and force AES.' `
      -DetailFile $file
  }
  elseif ($oldPasswords.Count -gt 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Kerberoastable Accounts' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($spnUsers.Count) account(s) are Kerberoastable, $($oldPasswords.Count) with a password older than $ServiceAccountPasswordMaxAgeDays days." `
      -Remediation 'Migrate these to group managed service accounts, which rotate their own 120-character passwords. Where that is not possible, rotate to a long random password and enable AES.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Kerberoastable Accounts' -Status 'Warn' -Severity 'Low' `
      -Summary "$($spnUsers.Count) account(s) are Kerberoastable, none privileged and none with an old password." `
      -Remediation 'Nothing urgent. Prefer group managed service accounts for any new service.' `
      -DetailFile $file
  }
}

function _TestAsRepRoastableAccounts {
  Write-Verbose '..running function _TestAsRepRoastableAccounts'

  try {
    $accounts = @(Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
      -Properties adminCount, PasswordLastSet -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'AS-REP Roastable Accounts' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query pre-authentication settings: $($_.Exception.Message)"
    return
  }

  if ($accounts.Count -eq 0) {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'AS-REP Roastable Accounts' -Status 'Pass' -Severity 'Info' `
      -Summary 'All enabled accounts require Kerberos pre-authentication.'
    return
  }

  $detail = $accounts | Select-Object Name, SamAccountName, @{ N = 'Privileged'; E = { $_.adminCount -eq 1 } }, PasswordLastSet, DistinguishedName
  $file = _ExportDetail -InputObject $detail -FileName 'AsRepRoastableAccounts.csv'
  $privileged = @($detail | Where-Object { $_.Privileged })
  $severity = if ($privileged.Count -gt 0) { 'High' } else { 'Medium' }

  _AddFinding -Category 'Delegation and Kerberos' -Check 'AS-REP Roastable Accounts' -Status 'Fail' -Severity $severity `
    -Summary "$($accounts.Count) enabled account(s) do not require Kerberos pre-authentication$(if ($privileged.Count -gt 0) { ", $($privileged.Count) of them privileged" })." `
    -Remediation 'Clear "Do not require Kerberos preauthentication" on each account. An attacker can request an encrypted blob for these accounts with no credentials at all and crack it offline.' `
    -DetailFile $file
}

function _TestWeakKerberosEncryption {
  Write-Verbose '..running function _TestWeakKerberosEncryption'

  $results = New-Object System.Collections.Generic.List[pscustomobject]

  try {
    # 0x200000 UseDESKeyOnly
    $desOnly = @(Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' `
      -Properties samAccountName, objectClass -ErrorAction Stop)
    foreach ($o in $desOnly) {
      $results.Add([pscustomobject]@{
        Name = $o.Name; SamAccountName = $o.samAccountName; ObjectClass = $o.objectClass
        Issue = 'DES only (UseDESKeyOnly)'; SupportedEncryptionTypes = 'DES'
      })
    }

    # Accounts with an explicit encryption type that includes a DES bit (1 or 2) or excludes both AES bits (8, 16).
    $withEnc = @(Get-ADObject -LDAPFilter '(&(msDS-SupportedEncryptionTypes=*)(|(objectClass=user)(objectClass=computer)))' `
      -Properties samAccountName, objectClass, 'msDS-SupportedEncryptionTypes' -ErrorAction Stop)
    foreach ($o in $withEnc) {
      $enc = $o.'msDS-SupportedEncryptionTypes'
      if ($null -eq $enc) { continue }
      $issue = $null
      if (($enc -band 3) -ne 0) { $issue = 'DES enabled' }
      elseif (($enc -band 24) -eq 0) { $issue = 'No AES support (RC4 only)' }
      if ($issue) {
        $results.Add([pscustomobject]@{
          Name = $o.Name; SamAccountName = $o.samAccountName; ObjectClass = $o.objectClass
          Issue = $issue; SupportedEncryptionTypes = $enc
        })
      }
    }
  }
  catch {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Weak Kerberos Encryption' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query Kerberos encryption types: $($_.Exception.Message)"
    return
  }

  if ($results.Count -gt 0) {
    $file = _ExportDetail -InputObject $results -FileName 'WeakKerberosEncryption.csv'
    $desCount = @($results | Where-Object { $_.Issue -like 'DES*' }).Count
    $severity = if ($desCount -gt 0) { 'High' } else { 'Medium' }
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Weak Kerberos Encryption' -Status 'Fail' -Severity $severity `
      -Summary "$($results.Count) object(s) use weak Kerberos encryption ($desCount with DES enabled)." `
      -Remediation 'Set msDS-SupportedEncryptionTypes to 24 (AES128 + AES256) on these accounts after confirming the service supports AES. DES is broken and RC4 is what makes Kerberoasting cheap.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Delegation and Kerberos' -Check 'Weak Kerberos Encryption' -Status 'Pass' -Severity 'Info' `
      -Summary 'No accounts are explicitly configured for DES, and none with an explicit setting lack AES.'
  }
}

#...................................
# Credential exposure
#...................................

function _TestGppPasswords {
  Write-Verbose '..running function _TestGppPasswords'

  if ($SkipSysvolScan) {
    _AddFinding -Category 'Credential Exposure' -Check 'Group Policy Preferences Passwords' -Status 'Info' -Severity 'Info' `
      -Summary 'Skipped because -SkipSysvolScan was specified.'
    return
  }

  $policyPath = "\\$($script:Domain.DNSRoot)\SYSVOL\$($script:Domain.DNSRoot)\Policies"
  if (-not (Test-Path -Path $policyPath)) {
    _AddFinding -Category 'Credential Exposure' -Check 'Group Policy Preferences Passwords' -Status 'Error' -Severity 'Info' `
      -Summary "Could not reach the SYSVOL policies share at $policyPath."
    return
  }

  $hits = New-Object System.Collections.Generic.List[pscustomobject]
  try {
    $xmlFiles = @(Get-ChildItem -Path $policyPath -Recurse -Include '*.xml' -File -ErrorAction SilentlyContinue)
    foreach ($xmlFile in $xmlFiles) {
      $matched = Select-String -Path $xmlFile.FullName -Pattern 'cpassword\s*=\s*"[^"]+"' -ErrorAction SilentlyContinue
      if ($matched) {
        $hits.Add([pscustomobject]@{
          File     = $xmlFile.FullName
          FileType = $xmlFile.Name
          Line     = ($matched | Select-Object -First 1).LineNumber
        })
      }
    }
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'Group Policy Preferences Passwords' -Status 'Error' -Severity 'Info' `
      -Summary "Error scanning SYSVOL for cpassword: $($_.Exception.Message)"
    return
  }

  if ($hits.Count -gt 0) {
    $file = _ExportDetail -InputObject $hits -FileName 'GppPasswords.csv'
    _AddFinding -Category 'Credential Exposure' -Check 'Group Policy Preferences Passwords' -Status 'Fail' -Severity 'High' `
      -Summary "$($hits.Count) Group Policy Preferences file(s) in SYSVOL contain a cpassword value." `
      -Remediation 'The AES key that protects cpassword is published by Microsoft, so these passwords are plaintext to any domain user. Change the password on every affected account, then delete the preference item and the leftover XML.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Credential Exposure' -Check 'Group Policy Preferences Passwords' -Status 'Pass' -Severity 'Info' `
      -Summary "No cpassword values found across $($xmlFiles.Count) Group Policy XML file(s)."
  }
}

function _TestPasswordsInAttributes {
  Write-Verbose '..running function _TestPasswordsInAttributes'

  $pattern = 'pass(word)?\s*[:=]|pwd\s*[:=]|passwd'
  $hits = New-Object System.Collections.Generic.List[pscustomobject]

  try {
    $users = @(Get-ADUser -Filter * -Properties Description, Info, Enabled -ErrorAction Stop)
    foreach ($u in $users) {
      foreach ($attribute in @('Description', 'Info')) {
        $value = $u.$attribute
        if ($value -and $value -match $pattern) {
          $hits.Add([pscustomobject]@{
            ObjectClass    = 'user'
            Name           = $u.Name
            SamAccountName = $u.SamAccountName
            Enabled        = $u.Enabled
            Attribute      = $attribute
            Value          = $value
          })
        }
      }
    }

    $computers = @(Get-ADComputer -Filter * -Properties Description, Enabled -ErrorAction Stop)
    foreach ($c in $computers) {
      if ($c.Description -and $c.Description -match $pattern) {
        $hits.Add([pscustomobject]@{
          ObjectClass    = 'computer'
          Name           = $c.Name
          SamAccountName = $c.SamAccountName
          Enabled        = $c.Enabled
          Attribute      = 'Description'
          Value          = $c.Description
        })
      }
    }
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'Passwords in Object Attributes' -Status 'Error' -Severity 'Info' `
      -Summary "Could not scan description and info attributes: $($_.Exception.Message)"
    return
  }

  if ($hits.Count -gt 0) {
    $file = _ExportDetail -InputObject $hits -FileName 'PasswordsInAttributes.csv'
    _AddFinding -Category 'Credential Exposure' -Check 'Passwords in Object Attributes' -Status 'Fail' -Severity 'High' `
      -Summary "$($hits.Count) object(s) have a password-like string in their description or info attribute." `
      -Remediation 'Every domain user can read these attributes. Change any password that appears there, then clear the attribute. Check the export before acting - some hits will be harmless text such as "password reset by helpdesk".' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Credential Exposure' -Check 'Passwords in Object Attributes' -Status 'Pass' -Severity 'Info' `
      -Summary 'No password-like strings found in description or info attributes.'
  }
}

function _TestSysvolScriptCredentials {
  Write-Verbose '..running function _TestSysvolScriptCredentials'

  if ($SkipSysvolScan) {
    _AddFinding -Category 'Credential Exposure' -Check 'Credentials in SYSVOL Scripts' -Status 'Info' -Severity 'Info' `
      -Summary 'Skipped because -SkipSysvolScan was specified.'
    return
  }

  $sysvolPath = "\\$($script:Domain.DNSRoot)\SYSVOL\$($script:Domain.DNSRoot)"
  if (-not (Test-Path -Path $sysvolPath)) {
    _AddFinding -Category 'Credential Exposure' -Check 'Credentials in SYSVOL Scripts' -Status 'Error' -Severity 'Info' `
      -Summary "Could not reach SYSVOL at $sysvolPath."
    return
  }

  $pattern = 'password\s*[:=]|/savecred|net\s+use\s+.*\s/user:|ConvertTo-SecureString\s+.*-AsPlainText|-Password\s+[''"]'
  $extensions = @('*.bat', '*.cmd', '*.ps1', '*.vbs', '*.kix', '*.txt', '*.ini')
  $hits = New-Object System.Collections.Generic.List[pscustomobject]

  try {
    $files = @(Get-ChildItem -Path $sysvolPath -Recurse -Include $extensions -File -ErrorAction SilentlyContinue)
    foreach ($scriptFile in $files) {
      $matched = Select-String -Path $scriptFile.FullName -Pattern $pattern -ErrorAction SilentlyContinue
      if ($matched) {
        foreach ($m in ($matched | Select-Object -First 3)) {
          $hits.Add([pscustomobject]@{
            File        = $scriptFile.FullName
            LineNumber  = $m.LineNumber
            MatchedLine = $m.Line.Trim()
          })
        }
      }
    }
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'Credentials in SYSVOL Scripts' -Status 'Error' -Severity 'Info' `
      -Summary "Error scanning SYSVOL scripts: $($_.Exception.Message)"
    return
  }

  if ($hits.Count -gt 0) {
    $file = _ExportDetail -InputObject $hits -FileName 'SysvolScriptCredentials.csv'
    _AddFinding -Category 'Credential Exposure' -Check 'Credentials in SYSVOL Scripts' -Status 'Fail' -Severity 'High' `
      -Summary "$($hits.Count) line(s) across SYSVOL scripts look like they contain credentials." `
      -Remediation 'SYSVOL is world-readable to every domain user. Review each hit, rotate any real credential found, and move the logon script to a group managed service account or a scheduled task on the target instead.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Credential Exposure' -Check 'Credentials in SYSVOL Scripts' -Status 'Pass' -Severity 'Info' `
      -Summary "No credential-like strings found across $($files.Count) SYSVOL script file(s)."
  }
}

function _TestLapsCoverage {
  Write-Verbose '..running function _TestLapsCoverage'

  $legacyAttribute  = 'ms-Mcs-AdmPwdExpirationTime'
  $modernAttribute  = 'msLAPS-PasswordExpirationTime'
  $schemaLegacy = $false
  $schemaModern = $false

  try {
    $schemaLegacy = [bool](Get-ADObject -SearchBase $script:SchemaNC -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -ErrorAction Stop)
    $schemaModern = [bool](Get-ADObject -SearchBase $script:SchemaNC -LDAPFilter '(lDAPDisplayName=msLAPS-Password)' -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'LAPS Coverage' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the schema to check for LAPS: $($_.Exception.Message)"
    return
  }

  if (-not $schemaLegacy -and -not $schemaModern) {
    _AddFinding -Category 'Credential Exposure' -Check 'LAPS Coverage' -Status 'Fail' -Severity 'High' `
      -Summary 'Neither the legacy LAPS nor the Windows LAPS schema extension is present. Local administrator passwords are not centrally managed.' `
      -Remediation 'Deploy Windows LAPS. A single shared local administrator password across the estate is the fastest route from one compromised workstation to all of them.'
    return
  }

  $attribute = if ($schemaModern) { $modernAttribute } else { $legacyAttribute }
  $schemaName = if ($schemaModern) { 'Windows LAPS' } else { 'legacy Microsoft LAPS' }

  try {
    $enabledComputers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem, LastLogonDate, $attribute -ErrorAction Stop)
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'LAPS Coverage' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the $attribute attribute on computer objects: $($_.Exception.Message)"
    return
  }

  # Only count machines that are actually alive, otherwise long-dead objects skew the coverage figure.
  $cutoff = (Get-Date).AddDays(-$StaleAccountDays)
  $active = @($enabledComputers | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -ge $cutoff })
  $missing = @($active | Where-Object { -not $_.$attribute })

  $detail = $missing | Select-Object Name, OperatingSystem, LastLogonDate, DistinguishedName
  $file = _ExportDetail -InputObject $detail -FileName 'LapsNotManaged.csv'

  if ($active.Count -eq 0) {
    _AddFinding -Category 'Credential Exposure' -Check 'LAPS Coverage' -Status 'Info' -Severity 'Info' `
      -Summary "The $schemaName schema is present, but no computers have logged on within $StaleAccountDays days to measure coverage against."
    return
  }

  $coverage = [math]::Round((($active.Count - $missing.Count) / $active.Count) * 100, 1)
  if ($missing.Count -gt 0) {
    $severity = if ($coverage -lt 50) { 'High' } else { 'Medium' }
    _AddFinding -Category 'Credential Exposure' -Check 'LAPS Coverage' -Status 'Warn' -Severity $severity `
      -Summary "The $schemaName schema is present, but only $coverage% coverage - $($missing.Count) of $($active.Count) active computer(s) have no managed local admin password." `
      -Remediation 'Check the LAPS GPO scope and that the client-side extension is installed on the machines listed. Schema present is not the same as deployed.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Credential Exposure' -Check 'LAPS Coverage' -Status 'Pass' -Severity 'Info' `
      -Summary "$schemaName covers all $($active.Count) active computer(s)."
  }
}

function _TestPasswordFlags {
  Write-Verbose '..running function _TestPasswordFlags'

  try {
    $reversible = @(Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=128)' -Properties Enabled -ErrorAction Stop)
    if ($reversible.Count -gt 0) {
      $file = _ExportDetail -InputObject ($reversible | Select-Object Name, SamAccountName, Enabled, DistinguishedName) `
        -FileName 'ReversibleEncryption.csv'
      _AddFinding -Category 'Credential Exposure' -Check 'Reversible Password Encryption' -Status 'Fail' -Severity 'High' `
        -Summary "$($reversible.Count) account(s) store their password with reversible encryption." `
        -Remediation 'Clear the flag and force a password change on each. Reversible encryption stores the password in a form that can be decrypted back to plaintext by anyone who can read the directory database.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Credential Exposure' -Check 'Reversible Password Encryption' -Status 'Pass' -Severity 'Info' `
        -Summary 'No accounts use reversible password encryption.'
    }
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'Reversible Password Encryption' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query reversible encryption: $($_.Exception.Message)"
  }

  try {
    $notRequired = @(Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -ErrorAction Stop)
    if ($notRequired.Count -gt 0) {
      $file = _ExportDetail -InputObject ($notRequired | Select-Object Name, SamAccountName, DistinguishedName) `
        -FileName 'PasswordNotRequired.csv'
      _AddFinding -Category 'Credential Exposure' -Check 'Password Not Required' -Status 'Fail' -Severity 'High' `
        -Summary "$($notRequired.Count) enabled account(s) are flagged as not requiring a password." `
        -Remediation 'Clear PASSWD_NOTREQD on each and set a password. These accounts can be left with a blank password regardless of the domain policy.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Credential Exposure' -Check 'Password Not Required' -Status 'Pass' -Severity 'Info' `
        -Summary 'No enabled accounts are flagged as not requiring a password.'
    }
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'Password Not Required' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query the password-not-required flag: $($_.Exception.Message)"
  }

  try {
    $neverExpires = @(Get-ADUser -LDAPFilter '(&(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
      -Properties PasswordLastSet, ServicePrincipalName, adminCount -ErrorAction Stop)
    if ($neverExpires.Count -gt 0) {
      $detail = $neverExpires | Select-Object Name, SamAccountName, PasswordLastSet,
        @{ N = 'Privileged'; E = { $_.adminCount -eq 1 } },
        @{ N = 'HasSPN'; E = { [bool]$_.ServicePrincipalName } }, DistinguishedName
      $file = _ExportDetail -InputObject $detail -FileName 'PasswordNeverExpires.csv'
      $privileged = @($detail | Where-Object { $_.Privileged })
      $severity = if ($privileged.Count -gt 0) { 'High' } else { 'Medium' }
      _AddFinding -Category 'Credential Exposure' -Check 'Password Never Expires' -Status 'Warn' -Severity $severity `
        -Summary "$($neverExpires.Count) enabled account(s) have a non-expiring password$(if ($privileged.Count -gt 0) { ", $($privileged.Count) of them privileged" })." `
        -Remediation 'For service accounts, migrate to group managed service accounts rather than simply clearing the flag. For human accounts there is no good reason for it - clear the flag and let policy apply.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Credential Exposure' -Check 'Password Never Expires' -Status 'Pass' -Severity 'Info' `
        -Summary 'No enabled accounts have a non-expiring password.'
    }
  }
  catch {
    _AddFinding -Category 'Credential Exposure' -Check 'Password Never Expires' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query the password-never-expires flag: $($_.Exception.Message)"
  }
}

#...................................
# Stale objects
#...................................

function _TestStaleAccounts {
  Write-Verbose '..running function _TestStaleAccounts'

  $cutoff = (Get-Date).AddDays(-$StaleAccountDays)
  $createdCutoff = (Get-Date).AddDays(-$NeverLoggedOnMinAgeDays)

  try {
    $users = @(Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate, whenCreated, PasswordLastSet -ErrorAction Stop)
    $stale = @($users | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff })
    $neverLoggedOn = @($users | Where-Object { -not $_.LastLogonDate -and $_.whenCreated -lt $createdCutoff })

    if ($stale.Count -gt 0) {
      $file = _ExportDetail -InputObject ($stale | Select-Object Name, SamAccountName, LastLogonDate, PasswordLastSet, DistinguishedName) `
        -FileName 'StaleUserAccounts.csv'
      _AddFinding -Category 'Stale Objects' -Check 'Stale User Accounts' -Status 'Warn' -Severity 'Medium' `
        -Summary "$($stale.Count) enabled user account(s) have not logged on in $StaleAccountDays days." `
        -Remediation 'Disable them, move them to a disabled-accounts OU, and delete after an agreed retention period. Every dormant enabled account is a credential nobody is watching.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Stale Objects' -Check 'Stale User Accounts' -Status 'Pass' -Severity 'Info' `
        -Summary "No enabled user accounts are stale beyond $StaleAccountDays days."
    }

    if ($neverLoggedOn.Count -gt 0) {
      $file = _ExportDetail -InputObject ($neverLoggedOn | Select-Object Name, SamAccountName, whenCreated, DistinguishedName) `
        -FileName 'NeverLoggedOnAccounts.csv'
      _AddFinding -Category 'Stale Objects' -Check 'Never Logged On Accounts' -Status 'Warn' -Severity 'Medium' `
        -Summary "$($neverLoggedOn.Count) enabled account(s) created more than $NeverLoggedOnMinAgeDays days ago have never logged on." `
        -Remediation 'These are usually leftovers from a bulk import or a starter who never arrived. Confirm and delete - they often still carry their initial password.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Stale Objects' -Check 'Never Logged On Accounts' -Status 'Pass' -Severity 'Info' `
        -Summary "No enabled accounts older than $NeverLoggedOnMinAgeDays days have never logged on."
    }
  }
  catch {
    _AddFinding -Category 'Stale Objects' -Check 'Stale User Accounts' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query user accounts: $($_.Exception.Message)"
  }

  try {
    $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties LastLogonDate, OperatingSystem, whenCreated -ErrorAction Stop)
    $stale = @($computers | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff })

    if ($stale.Count -gt 0) {
      $file = _ExportDetail -InputObject ($stale | Select-Object Name, OperatingSystem, LastLogonDate, DistinguishedName) `
        -FileName 'StaleComputerAccounts.csv'
      _AddFinding -Category 'Stale Objects' -Check 'Stale Computer Accounts' -Status 'Warn' -Severity 'Medium' `
        -Summary "$($stale.Count) enabled computer account(s) have not authenticated in $StaleAccountDays days." `
        -Remediation 'Disable and then delete. A stale computer object is a machine account whose password never rotates, and it inflates every other count in this report.' `
        -DetailFile $file
    }
    else {
      _AddFinding -Category 'Stale Objects' -Check 'Stale Computer Accounts' -Status 'Pass' -Severity 'Info' `
        -Summary "No enabled computer accounts are stale beyond $StaleAccountDays days."
    }
  }
  catch {
    _AddFinding -Category 'Stale Objects' -Check 'Stale Computer Accounts' -Status 'Error' -Severity 'Info' `
      -Summary "Could not query computer accounts: $($_.Exception.Message)"
  }
}

#...................................
# Domain controller hardening
#...................................

function _TestDomainControllerHardening {
  Write-Verbose '..running function _TestDomainControllerHardening'

  if ($SkipRemoteChecks) {
    _AddFinding -Category 'DC Hardening' -Check 'Domain Controller Hardening' -Status 'Info' -Severity 'Info' `
      -Summary 'Skipped because -SkipRemoteChecks was specified.'
    return
  }

  $results = New-Object System.Collections.Generic.List[pscustomobject]

  foreach ($dc in $script:AllDCs) {
    $name = $dc.HostName

    # Every field starts at Unknown so one unreachable DC never blanks the row or aborts the run.
    $row = [ordered]@{
      DomainController        = $name
      OperatingSystem         = $dc.OperatingSystem
      Smb1Enabled             = 'Unknown'
      SmbSigningRequired      = 'Unknown'
      LdapSigningRequired     = 'Unknown'
      LdapChannelBinding      = 'Unknown'
      LmCompatibilityLevel    = 'Unknown'
      PrintSpooler            = 'Unknown'
      DsrmAdminLogonBehavior  = 'Unknown'
    }

    $smb1 = _GetRemoteRegistryValue -ComputerName $name -SubKey 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'SMB1'
    if ("$smb1" -eq 'Unreachable') { $row.Smb1Enabled = 'Unreachable' }
    elseif ($null -eq $smb1)     { $row.Smb1Enabled = 'Not set (default enabled)' }
    elseif ($smb1 -eq 0)         { $row.Smb1Enabled = 'N' }
    else                         { $row.Smb1Enabled = 'Y' }

    $signing = _GetRemoteRegistryValue -ComputerName $name -SubKey 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'RequireSecuritySignature'
    if ("$signing" -eq 'Unreachable') { $row.SmbSigningRequired = 'Unreachable' }
    elseif ($signing -eq 1)         { $row.SmbSigningRequired = 'Y' }
    elseif ($null -eq $signing)     { $row.SmbSigningRequired = 'Not set' }
    else                            { $row.SmbSigningRequired = 'N' }

    $ldapSigning = _GetRemoteRegistryValue -ComputerName $name -SubKey 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'LDAPServerIntegrity'
    if ("$ldapSigning" -eq 'Unreachable') { $row.LdapSigningRequired = 'Unreachable' }
    elseif ($ldapSigning -eq 2)         { $row.LdapSigningRequired = 'Y' }
    elseif ($null -eq $ldapSigning)     { $row.LdapSigningRequired = 'Not set (default 1, negotiated)' }
    else                                { $row.LdapSigningRequired = "N (value $ldapSigning)" }

    $channelBinding = _GetRemoteRegistryValue -ComputerName $name -SubKey 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ValueName 'LdapEnforceChannelBinding'
    if ("$channelBinding" -eq 'Unreachable') { $row.LdapChannelBinding = 'Unreachable' }
    elseif ($null -eq $channelBinding)     { $row.LdapChannelBinding = 'Not set (disabled)' }
    elseif ($channelBinding -ge 1)         { $row.LdapChannelBinding = "Y (value $channelBinding)" }
    else                                   { $row.LdapChannelBinding = 'N' }

    $lmLevel = _GetRemoteRegistryValue -ComputerName $name -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'LmCompatibilityLevel'
    if ("$lmLevel" -eq 'Unreachable') { $row.LmCompatibilityLevel = 'Unreachable' }
    elseif ($null -eq $lmLevel)     { $row.LmCompatibilityLevel = 'Not set' }
    else                            { $row.LmCompatibilityLevel = $lmLevel }

    $dsrm = _GetRemoteRegistryValue -ComputerName $name -SubKey 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'DsrmAdminLogonBehavior'
    if ("$dsrm" -eq 'Unreachable') { $row.DsrmAdminLogonBehavior = 'Unreachable' }
    elseif ($null -eq $dsrm)     { $row.DsrmAdminLogonBehavior = 'Not set (DSRM only)' }
    else                         { $row.DsrmAdminLogonBehavior = $dsrm }

    try {
      $spooler = Get-Service -Name 'Spooler' -ComputerName $name -ErrorAction Stop
      $row.PrintSpooler = $spooler.Status.ToString()
    }
    catch {
      $row.PrintSpooler = 'Unreachable'
    }

    $results.Add([pscustomobject]$row)
  }

  $file = _ExportDetail -InputObject $results -FileName 'DomainControllerHardening.csv'

  $unreachable = @($results | Where-Object { $_.Smb1Enabled -eq 'Unreachable' })
  if ($unreachable.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'Domain Controller Reachability' -Status 'Warn' -Severity 'Info' `
      -Summary "$($unreachable.Count) of $($results.Count) domain controller(s) could not be queried by remote registry or WinRM." `
      -Remediation 'Run the audit from a management host with remote registry or WinRM access, or check these settings by hand on the affected controllers.' `
      -DetailFile $file
  }

  $smb1On = @($results | Where-Object { $_.Smb1Enabled -eq 'Y' -or $_.Smb1Enabled -like 'Not set*' })
  if ($smb1On.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'SMBv1 on Domain Controllers' -Status 'Fail' -Severity 'High' `
      -Summary "$($smb1On.Count) domain controller(s) have SMBv1 enabled or unset." `
      -Remediation 'Remove the SMB1 feature from every domain controller. SMBv1 has no signing worth the name and is the transport for a long list of well-known exploits.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'DC Hardening' -Check 'SMBv1 on Domain Controllers' -Status 'Pass' -Severity 'Info' `
      -Summary 'SMBv1 is explicitly disabled on all reachable domain controllers.' -DetailFile $file
  }

  $noLdapSigning = @($results | Where-Object { $_.LdapSigningRequired -ne 'Y' -and $_.LdapSigningRequired -ne 'Unreachable' })
  if ($noLdapSigning.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'LDAP Signing' -Status 'Fail' -Severity 'High' `
      -Summary "$($noLdapSigning.Count) domain controller(s) do not require LDAP signing." `
      -Remediation 'Set "Domain controller: LDAP server signing requirements" to "Require signing" via the Default Domain Controllers Policy. Audit first with event 2889 to find clients still binding without signing.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'DC Hardening' -Check 'LDAP Signing' -Status 'Pass' -Severity 'Info' `
      -Summary 'All reachable domain controllers require LDAP signing.' -DetailFile $file
  }

  $noChannelBinding = @($results | Where-Object { $_.LdapChannelBinding -like 'N*' -or $_.LdapChannelBinding -like 'Not set*' })
  if ($noChannelBinding.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'LDAP Channel Binding' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($noChannelBinding.Count) domain controller(s) do not enforce LDAP channel binding." `
      -Remediation 'Set LdapEnforceChannelBinding to 2. Together with LDAP signing this closes the relay path onto LDAPS.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'DC Hardening' -Check 'LDAP Channel Binding' -Status 'Pass' -Severity 'Info' `
      -Summary 'All reachable domain controllers enforce LDAP channel binding.' -DetailFile $file
  }

  $weakNtlm = @($results | Where-Object { $_.LmCompatibilityLevel -ne 'Unreachable' -and ($_.LmCompatibilityLevel -eq 'Not set' -or ($_.LmCompatibilityLevel -is [int] -and $_.LmCompatibilityLevel -lt 5)) })
  if ($weakNtlm.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'NTLM Compatibility Level' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($weakNtlm.Count) domain controller(s) accept NTLMv1 or LM authentication." `
      -Remediation 'Set LmCompatibilityLevel to 5 (refuse LM and NTLMv1) on the domain controllers via Group Policy. Check for legacy appliances first - old NAS boxes and MFPs are the usual casualties.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'DC Hardening' -Check 'NTLM Compatibility Level' -Status 'Pass' -Severity 'Info' `
      -Summary 'All reachable domain controllers refuse LM and NTLMv1.' -DetailFile $file
  }

  $spoolerRunning = @($results | Where-Object { $_.PrintSpooler -eq 'Running' })
  if ($spoolerRunning.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'Print Spooler on Domain Controllers' -Status 'Fail' -Severity 'High' `
      -Summary "The Print Spooler service is running on $($spoolerRunning.Count) domain controller(s)." `
      -Remediation 'Stop and disable the Print Spooler on every domain controller. It is both the PrintNightmare surface and the trigger used to coerce a DC into authenticating to an attacker.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'DC Hardening' -Check 'Print Spooler on Domain Controllers' -Status 'Pass' -Severity 'Info' `
      -Summary 'The Print Spooler is not running on any reachable domain controller.' -DetailFile $file
  }

  $dsrmRisky = @($results | Where-Object { $_.DsrmAdminLogonBehavior -is [int] -and $_.DsrmAdminLogonBehavior -eq 2 })
  if ($dsrmRisky.Count -gt 0) {
    _AddFinding -Category 'DC Hardening' -Check 'DSRM Logon Behaviour' -Status 'Warn' -Severity 'Medium' `
      -Summary "$($dsrmRisky.Count) domain controller(s) allow the DSRM account to log on normally (DsrmAdminLogonBehavior = 2)." `
      -Remediation 'Set DsrmAdminLogonBehavior to 0 or 1. Value 2 turns the DSRM account into a local backdoor that no domain policy governs.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'DC Hardening' -Check 'DSRM Logon Behaviour' -Status 'Pass' -Severity 'Info' `
      -Summary 'No reachable domain controller allows unrestricted DSRM logon.' -DetailFile $file
  }
}

#...................................
# Recoverability
#...................................

function _TestRecycleBin {
  Write-Verbose '..running function _TestRecycleBin'

  try {
    $feature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    if ($feature.EnabledScopes -and @($feature.EnabledScopes).Count -gt 0) {
      _AddFinding -Category 'Recoverability' -Check 'AD Recycle Bin' -Status 'Pass' -Severity 'Info' `
        -Summary 'The AD Recycle Bin is enabled.'
    }
    else {
      _AddFinding -Category 'Recoverability' -Check 'AD Recycle Bin' -Status 'Warn' -Severity 'Medium' `
        -Summary 'The AD Recycle Bin is not enabled.' `
        -Remediation 'Enable it with Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target <forest FQDN>. It is a one-way change, and without it an accidental bulk delete means an authoritative restore.'
    }
  }
  catch {
    _AddFinding -Category 'Recoverability' -Check 'AD Recycle Bin' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read the AD Recycle Bin state: $($_.Exception.Message)"
  }
}

function _TestTombstoneLifetime {
  Write-Verbose '..running function _TestTombstoneLifetime'

  try {
    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,$($script:ConfigNC)"
    $ds = Get-ADObject -Identity $dsPath -Properties tombstoneLifetime -ErrorAction Stop
    $lifetime = $ds.tombstoneLifetime
  }
  catch {
    _AddFinding -Category 'Recoverability' -Check 'Tombstone Lifetime' -Status 'Error' -Severity 'Info' `
      -Summary "Could not read tombstoneLifetime: $($_.Exception.Message)"
    return
  }

  if ($null -eq $lifetime) {
    _AddFinding -Category 'Recoverability' -Check 'Tombstone Lifetime' -Status 'Warn' -Severity 'Medium' `
      -Summary 'tombstoneLifetime is not set explicitly, so the directory falls back to 60 days.' `
      -Remediation 'Set tombstoneLifetime to 180 days. It caps how old a usable backup can be - at 60 days, a two-month-old backup is worthless.'
  }
  elseif ($lifetime -lt 180) {
    _AddFinding -Category 'Recoverability' -Check 'Tombstone Lifetime' -Status 'Warn' -Severity 'Medium' `
      -Summary "Tombstone lifetime is $lifetime days." `
      -Remediation 'Raise tombstoneLifetime to 180 days. Any backup older than this value cannot be restored, so it sets the real shelf life of your recovery position.'
  }
  else {
    _AddFinding -Category 'Recoverability' -Check 'Tombstone Lifetime' -Status 'Pass' -Severity 'Info' `
      -Summary "Tombstone lifetime is $lifetime days."
  }
}

function _TestBackupAge {
  Write-Verbose '..running function _TestBackupAge'

  try {
    $output = & repadmin /showbackup $script:Domain.DNSRoot 2>&1
  }
  catch {
    _AddFinding -Category 'Recoverability' -Check 'Directory Backup Age' -Status 'Error' -Severity 'Info' `
      -Summary "Could not run repadmin /showbackup: $($_.Exception.Message)"
    return
  }

  # repadmin writes the naming context and its backup timestamp on the same line, but the exact
  # layout varies by build - so track the last naming context seen and parse any date found.
  $backups = New-Object System.Collections.Generic.List[pscustomobject]
  $currentNC = 'Unknown'
  foreach ($line in $output) {
    $text = ([string]$line).Trim()
    if ($text -match '^(DC=|CN=)') { $currentNC = ($text -split '\s{2,}')[0].Trim() }
    if ($text -match '(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|\d{1,2}/\d{1,2}/\d{4}[^\d]+\d{1,2}:\d{2}|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4})') {
      $stamp = $Matches[1]
      $parsed = $null
      try { $parsed = [datetime]::Parse($stamp) }
      catch { $parsed = $null }

      if ($null -ne $parsed) {
        $backups.Add([pscustomobject]@{
          NamingContext = $currentNC
          LastBackup    = $parsed
          AgeDays       = [int](New-TimeSpan -Start $parsed -End (Get-Date)).TotalDays
        })
      }
    }
  }
  # Keep only the most recent timestamp per naming context.
  $backups = @($backups | Group-Object NamingContext | ForEach-Object {
    $_.Group | Sort-Object LastBackup -Descending | Select-Object -First 1
  })

  if ($backups.Count -eq 0) {
    _AddFinding -Category 'Recoverability' -Check 'Directory Backup Age' -Status 'Warn' -Severity 'High' `
      -Summary 'No directory backup timestamps could be read from repadmin /showbackup.' `
      -Remediation 'Confirm a system state backup of at least one domain controller is running and succeeding. An immature domain frequently has none, and without one there is no route back from a ransomware event.'
    return
  }

  $file = _ExportDetail -InputObject $backups -FileName 'DirectoryBackups.csv'
  $oldest = ($backups | Sort-Object AgeDays -Descending | Select-Object -First 1)

  if ($oldest.AgeDays -gt 30) {
    _AddFinding -Category 'Recoverability' -Check 'Directory Backup Age' -Status 'Fail' -Severity 'High' `
      -Summary "The oldest naming context backup is $($oldest.AgeDays) days old ($($oldest.NamingContext))." `
      -Remediation 'Restore a working system state backup schedule for at least two domain controllers, and test a restore. Note that a backup older than the tombstone lifetime cannot be used at all.' `
      -DetailFile $file
  }
  elseif ($oldest.AgeDays -gt 7) {
    _AddFinding -Category 'Recoverability' -Check 'Directory Backup Age' -Status 'Warn' -Severity 'Medium' `
      -Summary "The oldest naming context backup is $($oldest.AgeDays) days old." `
      -Remediation 'Tighten the backup schedule to at least weekly, ideally daily, on two domain controllers.' `
      -DetailFile $file
  }
  else {
    _AddFinding -Category 'Recoverability' -Check 'Directory Backup Age' -Status 'Pass' -Severity 'Info' `
      -Summary "All naming contexts were backed up within the last $($oldest.AgeDays) day(s)." -DetailFile $file
  }
}

#...................................
# Reporting
#...................................

function _HtmlEncode {
  param([Parameter(Mandatory = $false)][string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return '' }
  return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function _GetActionPlan {
  <#
    Returns the open findings (Warn or Fail) ordered by severity, highest first, ready to be
    numbered as an action plan.
  #>
  $order = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
  return @($script:Findings |
    Where-Object { $_.Status -in @('Warn', 'Fail') } |
    Sort-Object -Property @{ Expression = { $order[$_.Severity] } }, Category, Check)
}

function _WriteHtmlReport {
  Write-Verbose '..running function _WriteHtmlReport'

  $actionPlan = _GetActionPlan
  $counts = @{}
  foreach ($s in @('High', 'Medium', 'Low')) {
    $counts[$s] = @($actionPlan | Where-Object { $_.Severity -eq $s }).Count
  }
  $passCount  = @($script:Findings | Where-Object { $_.Status -eq 'Pass' }).Count
  $errorCount = @($script:Findings | Where-Object { $_.Status -eq 'Error' }).Count

  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine(@"
<!DOCTYPE html>
<html lang="en-GB">
<head>
<meta charset="utf-8" />
<title>AD Security Audit - $(_HtmlEncode $script:Domain.DNSRoot)</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; font-size: 10.5pt; color: #1a1a1a; margin: 24px; }
  h1 { font-size: 20pt; margin-bottom: 4px; }
  h2 { font-size: 14pt; margin-top: 32px; border-bottom: 2px solid #dddddd; padding-bottom: 4px; }
  h3 { font-size: 11.5pt; margin-top: 20px; }
  .meta { color: #555555; font-size: 9.5pt; margin-bottom: 24px; }
  table { border-collapse: collapse; width: 100%; font-size: 9.5pt; margin-bottom: 16px; }
  th { background: #333333; color: #ffffff; text-align: left; padding: 7px; }
  td { border-bottom: 1px solid #dddddd; padding: 7px; vertical-align: top; }
  tr:nth-child(even) td { background: #fafafa; }
  .sev-High { background: #c00000; color: #ffffff; font-weight: bold; text-align: center; }
  .sev-Medium { background: #ed7d31; color: #ffffff; font-weight: bold; text-align: center; }
  .sev-Low { background: #ffc000; color: #1a1a1a; font-weight: bold; text-align: center; }
  .sev-Info { background: #9dc3e6; color: #1a1a1a; text-align: center; }
  .st-Pass { background: #70ad47; color: #ffffff; text-align: center; }
  .st-Warn { background: #ffc000; color: #1a1a1a; text-align: center; }
  .st-Fail { background: #c00000; color: #ffffff; text-align: center; }
  .st-Info { background: #9dc3e6; color: #1a1a1a; text-align: center; }
  .st-Error { background: #7030a0; color: #ffffff; text-align: center; }
  .scorecard span { display: inline-block; padding: 10px 18px; margin-right: 8px; border-radius: 4px; font-weight: bold; }
  .num { width: 34px; text-align: center; font-weight: bold; }
  .footnote { color: #666666; font-size: 9pt; margin-top: 32px; }
  code { background: #f0f0f0; padding: 1px 4px; }
</style>
</head>
<body>
<h1>Active Directory Security Audit</h1>
<div class="meta">
  Domain: <strong>$(_HtmlEncode $script:Domain.DNSRoot)</strong> ($(_HtmlEncode $script:Domain.NetBIOSName)) &nbsp;|&nbsp;
  Forest: $(_HtmlEncode $script:Forest.Name) &nbsp;|&nbsp;
  Functional level: $(_HtmlEncode $script:Domain.DomainMode.ToString()) &nbsp;|&nbsp;
  Domain controllers: $(@($script:AllDCs).Count)<br />
  Generated: $(Get-Date -Format 'dddd dd MMMM yyyy HH:mm') &nbsp;|&nbsp;
  Run as: $(_HtmlEncode "$env:USERDOMAIN\$env:USERNAME") from $(_HtmlEncode $env:COMPUTERNAME)<br />
  All checks are read-only. Nothing in the directory was changed by this audit.
</div>

<div class="scorecard">
  <span class="sev-High">High: $($counts['High'])</span>
  <span class="sev-Medium">Medium: $($counts['Medium'])</span>
  <span class="sev-Low">Low: $($counts['Low'])</span>
  <span class="st-Pass">Passed: $passCount</span>
  <span class="st-Error">Not checked: $errorCount</span>
</div>
"@)

  # Action plan
  [void]$sb.AppendLine('<h2>Action plan</h2>')
  if ($actionPlan.Count -eq 0) {
    [void]$sb.AppendLine('<p>No findings were raised. Every check either passed or was not applicable.</p>')
  }
  else {
    [void]$sb.AppendLine('<p>Ordered by severity. Work down the list - the high severity items are the ones that change what an attacker can do today.</p>')
    [void]$sb.AppendLine('<table><tr><th class="num">#</th><th>Severity</th><th>Finding</th><th>What to do</th><th>Detail</th></tr>')
    $i = 0
    foreach ($f in $actionPlan) {
      $i++
      $detail = if ($f.DetailFile) { "<code>$(_HtmlEncode $f.DetailFile)</code>" } else { '-' }
      [void]$sb.AppendLine(("<tr><td class=""num"">{0}</td><td class=""sev-{1}"">{1}</td><td><strong>{2}</strong><br />{3}</td><td>{4}</td><td>{5}</td></tr>" -f `
        $i, $f.Severity, (_HtmlEncode $f.Check), (_HtmlEncode $f.Summary), (_HtmlEncode $f.Remediation), $detail))
    }
    [void]$sb.AppendLine('</table>')
  }

  # Full results by category
  [void]$sb.AppendLine('<h2>All checks by category</h2>')
  foreach ($category in (@($script:Findings | Select-Object -ExpandProperty Category -Unique))) {
    [void]$sb.AppendLine("<h3>$(_HtmlEncode $category)</h3>")
    [void]$sb.AppendLine('<table><tr><th>Check</th><th>Status</th><th>Severity</th><th>Summary</th></tr>')
    foreach ($f in ($script:Findings | Where-Object { $_.Category -eq $category })) {
      $sev = if ($f.Status -in @('Warn', 'Fail')) { $f.Severity } else { 'Info' }
      [void]$sb.AppendLine(("<tr><td>{0}</td><td class=""st-{1}"">{1}</td><td class=""sev-{2}"">{2}</td><td>{3}</td></tr>" -f `
        (_HtmlEncode $f.Check), $f.Status, $sev, (_HtmlEncode $f.Summary)))
    }
    [void]$sb.AppendLine('</table>')
  }

  # Detail files
  $detailFiles = @($script:Findings | Where-Object { $_.DetailFile } | Select-Object -ExpandProperty DetailFile -Unique | Sort-Object)
  if ($detailFiles.Count -gt 0) {
    [void]$sb.AppendLine('<h2>Detail exports</h2>')
    [void]$sb.AppendLine('<p>Each file sits alongside this report and lists the individual objects behind a finding.</p><ul>')
    foreach ($d in $detailFiles) { [void]$sb.AppendLine("<li><code>$(_HtmlEncode $d)</code></li>") }
    [void]$sb.AppendLine('</ul>')
  }

  [void]$sb.AppendLine("<p class=""footnote"">Generated by Get-ADSecurityAudit.ps1. Read-only audit - no directory objects, permissions or settings were modified. Findings are a starting point for discussion, not a compliance verdict.</p>")
  [void]$sb.AppendLine('</body></html>')

  $path = Join-Path $script:ReportFolder 'ADSecurityAudit.html'
  $sb.ToString() | Out-File -FilePath $path -Encoding UTF8
  return $path
}

function _WriteTextReport {
  Write-Verbose '..running function _WriteTextReport'

  $actionPlan = _GetActionPlan
  $lines = New-Object System.Collections.Generic.List[string]
  $rule = ('=' * 78)
  $thin = ('-' * 78)

  $lines.Add($rule)
  $lines.Add('ACTIVE DIRECTORY SECURITY AUDIT')
  $lines.Add($rule)
  $lines.Add("Domain            : $($script:Domain.DNSRoot) ($($script:Domain.NetBIOSName))")
  $lines.Add("Forest            : $($script:Forest.Name)")
  $lines.Add("Functional level  : $($script:Domain.DomainMode)")
  $lines.Add("Domain controllers: $(@($script:AllDCs).Count)")
  $lines.Add("Generated         : $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
  $lines.Add("Run as            : $env:USERDOMAIN\$env:USERNAME from $env:COMPUTERNAME")
  $lines.Add('')
  $lines.Add('All checks are read-only. Nothing in the directory was changed by this audit.')
  $lines.Add('')

  foreach ($s in @('High', 'Medium', 'Low')) {
    $lines.Add(("{0,-8} severity findings: {1}" -f $s, @($actionPlan | Where-Object { $_.Severity -eq $s }).Count))
  }
  $lines.Add(("{0,-8} checks passed     : {1}" -f '', @($script:Findings | Where-Object { $_.Status -eq 'Pass' }).Count))
  $lines.Add(("{0,-8} checks not run    : {1}" -f '', @($script:Findings | Where-Object { $_.Status -eq 'Error' }).Count))
  $lines.Add('')

  $lines.Add($rule)
  $lines.Add('ACTION PLAN (highest severity first)')
  $lines.Add($rule)
  if ($actionPlan.Count -eq 0) {
    $lines.Add('No findings were raised.')
  }
  else {
    $i = 0
    foreach ($f in $actionPlan) {
      $i++
      $lines.Add('')
      $lines.Add(("{0}. [{1}] {2} - {3}" -f $i, $f.Severity.ToUpper(), $f.Category, $f.Check))
      $lines.Add($thin)
      $lines.Add("   Finding : $($f.Summary)")
      if ($f.Remediation) { $lines.Add("   Action  : $($f.Remediation)") }
      if ($f.DetailFile)  { $lines.Add("   Detail  : $($f.DetailFile)") }
    }
  }

  $lines.Add('')
  $lines.Add($rule)
  $lines.Add('ALL CHECKS BY CATEGORY')
  $lines.Add($rule)
  foreach ($category in (@($script:Findings | Select-Object -ExpandProperty Category -Unique))) {
    $lines.Add('')
    $lines.Add($category.ToUpper())
    $lines.Add($thin)
    foreach ($f in ($script:Findings | Where-Object { $_.Category -eq $category })) {
      $lines.Add(("  [{0,-5}] {1}" -f $f.Status, $f.Check))
      $lines.Add("          $($f.Summary)")
    }
  }

  $lines.Add('')
  $lines.Add($rule)
  $lines.Add('Generated by Get-ADSecurityAudit.ps1 - read-only audit.')
  $lines.Add($rule)

  $path = Join-Path $script:ReportFolder 'ADSecurityAudit.txt'
  $lines | Out-File -FilePath $path -Encoding UTF8
  return $path
}

#...................................
# Main
#...................................

$ErrorActionPreference = 'Stop'

try {
  Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
  throw "The ActiveDirectory module could not be loaded. Install the RSAT AD DS tools and try again. $($_.Exception.Message)"
}

try {
  $script:Domain   = Get-ADDomain -ErrorAction Stop
  $script:Forest   = Get-ADForest -ErrorAction Stop
  $script:AllDCs   = @(Get-ADDomainController -Filter * -ErrorAction Stop)
  $rootDSE         = Get-ADRootDSE -ErrorAction Stop
  $script:ConfigNC = $rootDSE.configurationNamingContext
  $script:SchemaNC = $rootDSE.schemaNamingContext
}
catch {
  throw "Could not contact Active Directory. Run this from a domain-joined machine with the RSAT AD tools. $($_.Exception.Message)"
}

$script:Findings          = New-Object System.Collections.Generic.List[pscustomobject]
$script:PrivilegedMembers = @()

$script:ReportFolder = Join-Path $OutputPath ("{0}_ADSecurityAudit_{1}" -f $script:Domain.NetBIOSName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -Path $script:ReportFolder -ItemType Directory -Force | Out-Null

Write-Host ''
Write-Host "Active Directory security audit - $($script:Domain.DNSRoot)" -ForegroundColor Cyan
Write-Host "Read-only. Report folder: $script:ReportFolder" -ForegroundColor Cyan
Write-Host ''

# Individual checks manage their own errors, so one failure never stops the run.
$ErrorActionPreference = 'Continue'

_TestPasswordPolicy
_TestGuestAccount
_TestKrbtgtAge
_TestMachineAccountQuota
_TestAnonymousLdapBinds
_TestPreWindows2000Access

_TestPrivilegedGroups
_TestBuiltinAdministrator
_TestAdminCountOrphans
_TestProtectedUsers
_TestSensitiveAdminFlags
_TestDCSyncRights
_TestDangerousAcls
_TestDomainControllerOwnership

_TestUnconstrainedDelegation
_TestConstrainedDelegation
_TestResourceBasedDelegation
_TestKerberoastableAccounts
_TestAsRepRoastableAccounts
_TestWeakKerberosEncryption

_TestGppPasswords
_TestPasswordsInAttributes
_TestSysvolScriptCredentials
_TestLapsCoverage
_TestPasswordFlags

_TestStaleAccounts

_TestDomainControllerHardening

_TestRecycleBin
_TestTombstoneLifetime
_TestBackupAge

$script:Findings | Export-Csv -Path (Join-Path $script:ReportFolder 'Findings.csv') -NoTypeInformation -Encoding UTF8
$htmlPath = _WriteHtmlReport
$textPath = _WriteTextReport

$plan = _GetActionPlan
Write-Host ''
Write-Host 'Audit complete.' -ForegroundColor Cyan
Write-Host "  High   : $(@($plan | Where-Object { $_.Severity -eq 'High' }).Count)"   -ForegroundColor Red
Write-Host "  Medium : $(@($plan | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
Write-Host "  Low    : $(@($plan | Where-Object { $_.Severity -eq 'Low' }).Count)"    -ForegroundColor Yellow
Write-Host "  Passed : $(@($script:Findings | Where-Object { $_.Status -eq 'Pass' }).Count)" -ForegroundColor Green
Write-Host "  Errors : $(@($script:Findings | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Magenta
Write-Host ''
Write-Host "  HTML report : $htmlPath"
Write-Host "  Text report : $textPath"
Write-Host "  Findings CSV: $(Join-Path $script:ReportFolder 'Findings.csv')"
Write-Host ''
