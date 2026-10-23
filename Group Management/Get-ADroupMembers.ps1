param (
    [Parameter(Mandatory)]
    [string]$NameLike,

    [Parameter(Mandatory)]
    [string]$OutputPath
)

Import-Module ActiveDirectory

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

$groups = Get-ADGroup -Filter { Name -like $NameLike }

foreach ($group in $groups) {
    $fileName = $group.SamAccountName -replace '[\\/:*?"<>|]', '_'
    $csvPath = Join-Path -Path $OutputPath -ChildPath "$fileName.csv"

    Get-ADGroupMember -Identity $group |
        Select-Object Name, SamAccountName, ObjectClass, DistinguishedName |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "Exported: $csvPath"
}