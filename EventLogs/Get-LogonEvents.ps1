#Requires -Version 5.1
<#
.SYNOPSIS
    Get-LogonEvents.ps1 - Pull logon activity out of the Windows Security log for the last X minutes, hours or days.

.DESCRIPTION
    Queries the Security event log on one or more computers for logon-related events inside a
    rolling time window and returns one normalised object per event, so the output can be sorted,
    filtered, grouped or exported without having to know which EventData field lives where for
    each event ID. Read-only - it never touches the log or the machine it runs against.

    Event types (pick with -EventType, default is Success and Failure):

        Success             4624  An account was successfully logged on
        Failure             4625  An account failed to log on
        Logoff              4634  An account was logged off
                            4647  User initiated logoff
        ExplicitCredential  4648  A logon was attempted using explicit credentials (runas, etc.)
        LockUnlock          4800  The workstation was locked
                            4801  The workstation was unlocked
        All                 Everything above

    By default the well-known noise is dropped: SYSTEM, LOCAL/NETWORK SERVICE, ANONYMOUS LOGON,
    machine accounts (name ends in $), and the DWM-*/UMFD-* window manager and font driver
    sessions. Use -IncludeSystemAccounts to see them.

    Failed logons (4625) are decoded to a plain-English reason (bad password, account locked out,
    account disabled, ...) from the NTSTATUS sub-status code.

.PARAMETER Minutes
    Look back this many minutes from now. Mutually exclusive with -Hours and -Days.

.PARAMETER Hours
    Look back this many hours from now. Mutually exclusive with -Minutes and -Days.

.PARAMETER Days
    Look back this many days from now. Mutually exclusive with -Minutes and -Hours.

.PARAMETER ComputerName
    One or more computers to query. Defaults to the local machine. Remote queries need the
    Remote Event Log Management firewall rules open and a caller who can read the Security log.

.PARAMETER Credential
    Alternate credentials for remote computers. Ignored for the local machine.

.PARAMETER EventType
    Which logon event families to return. One or more of Success, Failure, Logoff,
    ExplicitCredential, LockUnlock, All. Default: Success, Failure.

.PARAMETER LogonType
    Only return events with these logon type numbers. Common values:
        2  Interactive (console)        3  Network (share, WinRM, etc.)
        4  Batch (scheduled task)       5  Service
        7  Unlock                       8  NetworkCleartext (basic auth, IIS)
        9  NewCredentials (runas /netonly)
       10  RemoteInteractive (RDP)     11  CachedInteractive (offline domain logon)

.PARAMETER UserName
    Wildcard filter on the account name (sAMAccountName, no domain), e.g. 'svc*' or 'jsmith'.

.PARAMETER SourceIp
    Wildcard filter on the source IP address, e.g. '10.1.*'.

.PARAMETER IncludeSystemAccounts
    Keep SYSTEM, service accounts, machine accounts and window manager sessions in the output.

.PARAMETER MaxEvents
    Stop reading each computer's log after this many matching raw events. Default is unlimited.
    Useful as a safety valve on a busy domain controller.

.PARAMETER Summary
    Instead of individual events, return one row per user + event type + result with a count and
    the first and last time seen. Handy for spotting spray attempts or a noisy service account.

.PARAMETER ExportCsv
    Also write the results to this CSV path. The objects are still sent to the pipeline.

.NOTES
    DISCLAIMER - USE AT YOUR OWN RISK
    This script is provided "as is", without warranty of any kind, express or implied. The author
    accepts no liability for any loss, damage or disruption arising from its use. It only reads
    the event log, but you are responsible for reviewing the code before running it.

    Reading the Security log requires local Administrator or membership of Event Log Readers.
    Nothing will come back unless "Audit Logon" (and for failures, "Audit Logon" failure or
    "Audit Account Lockout") is enabled in the local or GPO audit policy. Run
    auditpol /get /category:Logon/Logoff to check. Any output the script produces contains
    account names and source addresses - treat it as sensitive.

    Internal functions:
        _ResolveEventIds        _ConvertEventData
        _IsSystemAccount        _NewLogonRecord

.EXAMPLE
    .\Get-LogonEvents.ps1 -Hours 4
    Successful and failed logons on this machine in the last four hours.

.EXAMPLE
    .\Get-LogonEvents.ps1 -Minutes 30 -EventType Failure | Format-Table -AutoSize
    Failed logons in the last half hour with the decoded failure reason.

.EXAMPLE
    .\Get-LogonEvents.ps1 -Days 7 -ComputerName DC01, DC02 -EventType Failure -Summary
    Failed logon counts per user across both domain controllers for the last week.

.EXAMPLE
    .\Get-LogonEvents.ps1 -Days 1 -LogonType 10 -UserName 'admin*' -ExportCsv .\rdp-logons.csv
    RDP logons by admin accounts in the last day, also saved to CSV.

.EXAMPLE
    .\Get-LogonEvents.ps1 -Hours 1 -EventType All -IncludeSystemAccounts | Out-GridView
    Everything, unfiltered, for the last hour in a sortable grid.
#>

[CmdletBinding(DefaultParameterSetName = 'Hours')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Minutes')]
  [ValidateRange(1, 525600)]
  [int]$Minutes,

  [Parameter(Mandatory = $true, ParameterSetName = 'Hours')]
  [ValidateRange(1, 8760)]
  [int]$Hours,

  [Parameter(Mandatory = $true, ParameterSetName = 'Days')]
  [ValidateRange(1, 365)]
  [int]$Days,

  [Parameter(Mandatory = $false)]
  [Alias('CN', 'Server')]
  [string[]]$ComputerName = @($env:COMPUTERNAME),

  [Parameter(Mandatory = $false)]
  [System.Management.Automation.PSCredential]
  [System.Management.Automation.Credential()]
  $Credential = [System.Management.Automation.PSCredential]::Empty,

  [Parameter(Mandatory = $false)]
  [ValidateSet('Success', 'Failure', 'Logoff', 'ExplicitCredential', 'LockUnlock', 'All')]
  [string[]]$EventType = @('Success', 'Failure'),

  [Parameter(Mandatory = $false)]
  [ValidateRange(0, 13)]
  [int[]]$LogonType,

  [Parameter(Mandatory = $false)]
  [string]$UserName,

  [Parameter(Mandatory = $false)]
  [string]$SourceIp,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeSystemAccounts,

  [Parameter(Mandatory = $false)]
  [ValidateRange(1, [int]::MaxValue)]
  [int]$MaxEvents,

  [Parameter(Mandatory = $false)]
  [switch]$Summary,

  [Parameter(Mandatory = $false)]
  [string]$ExportCsv
)

#...................................
# Lookup tables
#...................................

$script:EventIdsByType = @{
  Success            = @(4624)
  Failure            = @(4625)
  Logoff             = @(4634, 4647)
  ExplicitCredential = @(4648)
  LockUnlock         = @(4800, 4801)
}

$script:EventLabels = @{
  4624 = 'Logon'
  4625 = 'Failed logon'
  4634 = 'Logoff'
  4647 = 'Logoff (user initiated)'
  4648 = 'Explicit credential logon'
  4800 = 'Workstation locked'
  4801 = 'Workstation unlocked'
}

$script:LogonTypeNames = @{
  0  = 'System'
  2  = 'Interactive'
  3  = 'Network'
  4  = 'Batch'
  5  = 'Service'
  7  = 'Unlock'
  8  = 'NetworkCleartext'
  9  = 'NewCredentials'
  10 = 'RemoteInteractive'
  11 = 'CachedInteractive'
  12 = 'CachedRemoteInteractive'
  13 = 'CachedUnlock'
}

# NTSTATUS codes seen in the Status / SubStatus fields of 4625. SubStatus is the useful one.
$script:FailureReasons = @{
  '0xC000005E' = 'No logon servers available'
  '0xC0000064' = 'User name does not exist'
  '0xC000006A' = 'Wrong password'
  '0xC000006D' = 'Bad user name or authentication information'
  '0xC000006E' = 'Account restriction (blank password, or policy)'
  '0xC000006F' = 'Outside permitted logon hours'
  '0xC0000070' = 'Workstation restriction'
  '0xC0000071' = 'Password expired'
  '0xC0000072' = 'Account disabled'
  '0xC00000DC' = 'SAM server in wrong state'
  '0xC0000133' = 'Clock skew too great'
  '0xC000015B' = 'Logon type not granted (user right missing)'
  '0xC000018C' = 'Trust relationship failed'
  '0xC0000192' = 'Netlogon service not started'
  '0xC0000193' = 'Account expired'
  '0xC0000224' = 'Password must be changed at next logon'
  '0xC0000234' = 'Account locked out'
  '0xC00002EE' = 'Unexpected error during logon'
  '0xC0000413' = 'Blocked by authentication firewall'
}

# Accounts and pseudo-domains that are dropped unless -IncludeSystemAccounts is given.
$script:SystemAccountNames = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', '-')
$script:SystemDomainNames = @('NT AUTHORITY', 'Window Manager', 'Font Driver Host')

#...................................
# Internal functions
#...................................

function _ResolveEventIds {
  <# Turns the -EventType selection into a distinct, sorted list of event IDs. #>
  param([Parameter(Mandatory = $true)][string[]]$Types)

  if ($Types -contains 'All') {
    $Types = @($script:EventIdsByType.Keys)
  }
  $ids = foreach ($t in $Types) { $script:EventIdsByType[$t] }
  return @($ids | Sort-Object -Unique)
}

function _ConvertEventData {
  <#
    Reads the EventData block of an event into a name -> value hashtable. Doing it by name via
    the XML is slower than indexing $event.Properties but does not break when Microsoft adds a
    field in the middle of the list, which they have done to 4624 more than once.
  #>
  param([Parameter(Mandatory = $true)][System.Diagnostics.Eventing.Reader.EventRecord]$Event)

  $data = @{}
  try {
    $xml = [xml]$Event.ToXml()
    foreach ($node in $xml.Event.EventData.Data) {
      if ($node.Name) { $data[$node.Name] = [string]$node.'#text' }
    }
  } catch {
    Write-Verbose "Could not parse EventData for record $($Event.RecordId): $($_.Exception.Message)"
  }
  return $data
}

function _IsSystemAccount {
  <# True for the built-in identities and machine accounts that clutter a logon report. #>
  param(
    [Parameter(Mandatory = $false)][string]$Name,
    [Parameter(Mandatory = $false)][string]$Domain
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
  if ($script:SystemAccountNames -contains $Name) { return $true }
  if ($script:SystemDomainNames -contains $Domain) { return $true }
  if ($Name.EndsWith('$')) { return $true }
  if ($Name -like 'DWM-*' -or $Name -like 'UMFD-*') { return $true }
  return $false
}

function _NewLogonRecord {
  <# Flattens one raw event into the common output shape regardless of its event ID. #>
  param(
    [Parameter(Mandatory = $true)][System.Diagnostics.Eventing.Reader.EventRecord]$Event,
    [Parameter(Mandatory = $true)][hashtable]$Data
  )

  $id = $Event.Id

  # 4648 is about the caller who supplied credentials, so the subject is the interesting user.
  if ($id -eq 4648) {
    $user = $Data['SubjectUserName']
    $domain = $Data['SubjectDomainName']
  } else {
    $user = $Data['TargetUserName']
    $domain = $Data['TargetDomainName']
  }

  $logonTypeNum = $null
  if ($Data.ContainsKey('LogonType') -and $Data['LogonType'] -match '^\d+$') {
    $logonTypeNum = [int]$Data['LogonType']
  }
  $logonTypeName = if ($null -ne $logonTypeNum) { $script:LogonTypeNames[$logonTypeNum] } else { $null }
  if ($null -ne $logonTypeNum -and -not $logonTypeName) { $logonTypeName = "Unknown ($logonTypeNum)" }

  $ip = $Data['IpAddress']
  if ($ip -eq '-' -or $ip -eq '::1' -or $ip -eq '127.0.0.1') { $ip = $null }
  if ($ip -like '::ffff:*') { $ip = $ip.Substring(7) }

  $workstation = $Data['WorkstationName']
  if ($workstation -eq '-') { $workstation = $null }

  $logonId = if ($Data.ContainsKey('TargetLogonId')) { $Data['TargetLogonId'] } else { $Data['LogonId'] }

  switch ($id) {
    4624 {
      $elevated = $Data['ElevatedToken'] -eq '%%1842'
      $result = if ($elevated) { 'Success (elevated)' } else { 'Success' }
    }
    4625 {
      $sub = $Data['SubStatus']
      $status = $Data['Status']
      $reason = $script:FailureReasons[$sub]
      if (-not $reason) { $reason = $script:FailureReasons[$status] }
      if (-not $reason) { $reason = "Unknown (status $status / sub-status $sub)" }
      $result = $reason
    }
    4648 {
      $target = "$($Data['TargetDomainName'])\$($Data['TargetUserName'])"
      $server = $Data['TargetServerName']
      $result = if ($server -and $server -ne 'localhost') { "Ran as $target on $server" } else { "Ran as $target" }
    }
    default { $result = $script:EventLabels[$id] }
  }

  $record = [pscustomobject]@{
    TimeCreated   = $Event.TimeCreated
    Computer      = $Event.MachineName
    EventId       = $id
    Event         = $script:EventLabels[$id]
    User          = if ($domain) { "$domain\$user" } else { $user }
    UserName      = $user
    Domain        = $domain
    LogonType     = $logonTypeNum
    LogonTypeName = $logonTypeName
    SourceIp      = $ip
    Workstation   = $workstation
    Process       = $Data['ProcessName']
    LogonProcess  = $Data['LogonProcessName']
    AuthPackage   = $Data['AuthenticationPackageName']
    Result        = $result
    LogonId       = $logonId
    RecordId      = $Event.RecordId
  }
  $record.PSObject.TypeNames.Insert(0, 'EventLogs.LogonEvent')
  return $record
}

#...................................
# Main
#...................................

# Keep the default table readable; everything else is still on the object for Select-Object.
Update-TypeData -TypeName 'EventLogs.LogonEvent' -Force -DefaultDisplayPropertySet @(
  'TimeCreated', 'Computer', 'Event', 'User', 'LogonTypeName', 'SourceIp', 'Workstation', 'Result'
)

$now = Get-Date
$startTime = switch ($PSCmdlet.ParameterSetName) {
  'Minutes' { $now.AddMinutes(-$Minutes) }
  'Hours'   { $now.AddHours(-$Hours) }
  'Days'    { $now.AddDays(-$Days) }
}
$windowText = switch ($PSCmdlet.ParameterSetName) {
  'Minutes' { "$Minutes minute(s)" }
  'Hours'   { "$Hours hour(s)" }
  'Days'    { "$Days day(s)" }
}

$eventIds = _ResolveEventIds -Types $EventType
Write-Verbose ("Window: {0:yyyy-MM-dd HH:mm:ss} to {1:yyyy-MM-dd HH:mm:ss}  Event IDs: {2}" -f $startTime, $now, ($eventIds -join ', '))

$filter = @{
  LogName   = 'Security'
  Id        = $eventIds
  StartTime = $startTime
  EndTime   = $now
}

$results = New-Object System.Collections.Generic.List[object]

# An unelevated session does not get Access Denied from the Security log - Get-WinEvent just
# reports "No events were found", which is easy to misread as a quiet machine.
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
  Write-Warning 'Not running elevated. The local Security log will look empty unless this account is in Event Log Readers.'
}

foreach ($computer in $ComputerName) {
  $isLocal = ($computer -in @('.', 'localhost', $env:COMPUTERNAME)) -or ($computer -like "$env:COMPUTERNAME.*")

  $getParams = @{
    FilterHashtable = $filter
    ErrorAction     = 'Stop'
  }
  if (-not $isLocal) {
    $getParams['ComputerName'] = $computer
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
      $getParams['Credential'] = $Credential
    }
  }
  if ($MaxEvents) { $getParams['MaxEvents'] = $MaxEvents }

  Write-Verbose "Querying $computer ..."
  $raw = @()
  try {
    $raw = @(Get-WinEvent @getParams)
  } catch {
    # Get-WinEvent throws rather than returning nothing when the filter matches zero events.
    if ($_.Exception.Message -like 'No events were found*') {
      Write-Verbose "No matching events on $computer."
    } else {
      Write-Warning "$computer - $($_.Exception.Message)"
      continue
    }
  }
  Write-Verbose "$computer returned $($raw.Count) raw event(s)."

  $kept = 0
  foreach ($evt in $raw) {
    $data = _ConvertEventData -Event $evt
    if ($data.Count -eq 0) { continue }

    $accountName = if ($evt.Id -eq 4648) { $data['SubjectUserName'] } else { $data['TargetUserName'] }
    $accountDomain = if ($evt.Id -eq 4648) { $data['SubjectDomainName'] } else { $data['TargetDomainName'] }

    if (-not $IncludeSystemAccounts -and (_IsSystemAccount -Name $accountName -Domain $accountDomain)) { continue }
    if ($UserName -and $accountName -notlike $UserName) { continue }
    if ($LogonType -and ($data['LogonType'] -notmatch '^\d+$' -or [int]$data['LogonType'] -notin $LogonType)) { continue }

    $record = _NewLogonRecord -Event $evt -Data $data
    if ($SourceIp -and $record.SourceIp -notlike $SourceIp) { continue }

    $results.Add($record)
    $kept++
  }
  Write-Verbose "$computer - kept $kept event(s) after filtering."
}

if ($results.Count -eq 0) {
  Write-Warning ("No logon events matched in the last $windowText. If you expected some, check the audit policy " +
    "with 'auditpol /get /category:Logon/Logoff' and make sure you are running elevated.")
  return
}

$sorted = $results | Sort-Object TimeCreated -Descending

if ($Summary) {
  $output = $sorted |
    Group-Object User, Event, Result |
    ForEach-Object {
      $first = $_.Group[0]
      [pscustomobject]@{
        User      = $first.User
        Event     = $first.Event
        Result    = $first.Result
        Count     = $_.Count
        FirstSeen = ($_.Group | Measure-Object TimeCreated -Minimum).Minimum
        LastSeen  = ($_.Group | Measure-Object TimeCreated -Maximum).Maximum
        SourceIps = (($_.Group.SourceIp | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
        Computers = (($_.Group.Computer | Sort-Object -Unique) -join ', ')
      }
    } |
    Sort-Object Count -Descending
} else {
  $output = $sorted
}

if ($ExportCsv) {
  try {
    $output | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Verbose "Exported $(@($output).Count) row(s) to $ExportCsv"
  } catch {
    Write-Warning "Could not write CSV to '$ExportCsv': $($_.Exception.Message)"
  }
}

$output
