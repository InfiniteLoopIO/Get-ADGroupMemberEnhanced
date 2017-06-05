#Requires -Modules 'ActiveDirectory'
#Requires -Version 3

<#
.Synopsis
   Get detailed AD information about current AD group members including those from trusted domains
.DESCRIPTION
   Create dynamic hashtable containing all trusted domain SIDs and current domain information
   Returned actual AD object from home domain when enumerating group membership
   Supports discovery of Users, Computers, or Group objects
   Can be run with recursive parameter
.EXAMPLE
    . C:\pathTo\Get-ADGroupMemberEnhanced.ps1 -groupName 'TestGroup1'
.EXAMPLE
    . C:\pathTo\Get-ADGroupMemberEnhanced.ps1 -groupName 'TestGroup1' -Recursive | Export-Csv c:\it\temp\TestGroup1.csv -NoTypeInformation -Encoding UTF8 -Force
#>
[CmdletBinding()]

Param
(
  [Parameter(Mandatory=$true,Position=0)]
  [ValidateScript({Get-ADGroup -Identity $_})]
  [string]$groupName,
  [Parameter(Mandatory=$false,Position=1)]
  [switch]$Recursive
)

# if dot sourcing this will only run once
if(!(Get-Variable -Name 'DomainSIDhash' -ea SilentlyContinue))
{
  Write-Host "Discovering trusted domains..."
  $global:DomainSIDhash = @{}
  Get-ADObject -f{objectclass -eq 'trusteddomain'} -prop 'securityIdentifier' | sort name | 
    % {Write-Host "Adding $($_.name)" -f Green;$global:DomainSIDhash[$_.SecurityIdentifier.Value] = $_.name}
 
  $currentDomain = Get-ADDomain
  $global:DomainSIDhash[$currentDomain.DomainSID.value] = $currentDomain.DNSRoot
  Write-Host "`nVerify powershell connectivity to each domain..."
  $global:DomainSIDhash.GetEnumerator() | sort value | % {write-host $_.value -f green;try {Get-ADDomain $_.value -ea Stop | Out-Null} catch {Write-Host $_.exception.message -f red; sleep 10; exit}}
}

#region HELPER_FUNCTIONS

function Get-ADObjectDomainName
{
  [cmdletbinding()]
  Param
  (
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateNotNullorEmpty()]
    [Microsoft.ActiveDirectory.Management.ADObject]$obj
  )
  
  $targetDomainSID = $obj.SID.AccountDomainSid.Value
  Write-Debug "$($Script:Myinvocation.command.name):`tGetting Domain Name for $targetDomainSID"

  if($Global:DomainSIDhash.Keys -contains $targetDomainSID)
  {
    Write-Debug "$($Script:Myinvocation.command.name):`tDomain name found $($Global:DomainSIDhash[$targetDomainSID])"
    $Global:DomainSIDhash[$targetDomainSID]
  }
  else
  {
    Write-Debug "$($Script:Myinvocation.command.name):`tDomain SID match not found for $($obj.distinguishedname)"
    "unknown"
  }
}

function Get-ADObjectDetails
{
  [cmdletbinding()]
  Param
  (
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateScript({$_.DomainName -ne 'unknown'})]
    [Microsoft.ActiveDirectory.Management.ADObject]$obj
  )

  Write-Debug "$($Script:Myinvocation.command.name):`t$($obj.distinguishedName)"
  $ADinfo = $null
  switch($obj.objectClass)
  {
    'computer' {
                 $ADinfo = try {Get-ADComputer $obj.SamAccountName -Server $obj.DomainName -ea stop} catch {$null}
                 if($ADinfo){Add-Member -InputObject $ADinfo -MemberType NoteProperty -Name 'DomainName' -Value $obj.DomainName -Force -ea stop}
               }
    'user'     {
                 $ADinfo = try {Get-ADUser $obj.SamAccountName -Server $obj.DomainName -ea stop} catch {$null}
                 if($ADinfo){Add-Member -InputObject $ADinfo -MemberType NoteProperty -Name 'DomainName' -Value $obj.DomainName -Force -ea stop}
               }
    'group'    {
                 $ADinfo = try {Get-ADGroup $obj.SamAccountName -Server $obj.DomainName -ea stop} catch {$null}
                 if($ADinfo){Add-Member -InputObject $ADinfo -MemberType NoteProperty -Name 'DomainName' -Value $obj.DomainName -Force -ea stop}
               }
    default    {Write-Debug "$($Script:Myinvocation.command.name):`t$($obj.objectClass) Object class not supported"}
  }

  $ADinfo
}

#endregion HELPER_FUNCTIONS

#region MAIN

$members = @()

if($recursive){$members = Get-ADGroupMember $groupName -Recursive}else{$members = Get-ADGroupMember $groupName}

if(@($members).Count -gt 0)
{
  $memberCount = $members.count
  Write-Host "`n`nGetting AD Domain Name for all $memberCount Group Members" -f Green
  $members | % {Add-Member -InputObject $_ -MemberType NoteProperty -Name 'DomainName' -Value (Get-ADObjectDomainName $_) -Force}

  Write-Host "Getting AD Object Home Domain Information for $memberCount Group Members..." -f Green
  $report = @{}
  $members | % {$report[$_.SID.Value] = (Get-ADObjectDetails $_)}
  $report.GetEnumerator() | % {$_.value}
}
else
{
  Write-Host "No members found in $groupName" -f Yellow
}

#endregion MAIN