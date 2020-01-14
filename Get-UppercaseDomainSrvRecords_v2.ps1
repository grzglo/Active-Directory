<# 
.SYNOPSIS 
Get-UppercaseDomainSrvRecords.ps1 - Finds SRV records with upper-case letters in name registered under _msdcs.  
 
.DESCRIPTION  
This script will locate your Active Directory integrated DNS servers and find SRV records with upper-case letters in name registered under _msdcs. 
 
.OUTPUTS 
Object, allows sorting, filtering and pipe output date.  
 
.COPYRIGHT
Grzegorz Glogowski - Microsoft Corporation 

.NOTES 
This script is provided "AS IS" with no warranties and confers no rights.
 
Change Log 
V1.00, 20200112 - Initial version
#> 

#Clear screen, usful when run in ISE
cls

<#
#Set up domain specification, borrowed from PyroTek3
#https://github.com/PyroTek3/PowerShell-AD-Recon/blob/master/Find-PSServiceAccounts
        if(-not $Domain)
        {
            $ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Domain = $ADDomainInfo.Name
        }
#>

#Get Active Directory forest and domain information
$forest = Get-ADForest
$domain = Get-ADDomain

#Find all DCs/DNS servers
$dns = (Resolve-DnsName $($domain.DNSRoot) -type NS | ? {$_.type -eq "A"}).Name

<#Alternative way to get DNS servers (LDAP query) - Windows Server 2008 R2 and older

#Find DNS servers
#https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx

$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.filter = "(servicePrincipalName=DNS*)"
$searchbase = "OU=Domain Controllers,"+$($domain.DistinguishedName)
$results = $search.Findall() | ?{ $_.path -like $searchbase }
$results = $search.Findall()
$dns = $results.Properties.dnshostname

#>

#$dcs = $domain.ReplicaDirectoryServers
$rootzone = $domain.DNSRoot
$msdcszone = "_msdcs." + $rootzone

#Get filtered set of SRV records from _msdcs
$dnsrecords = Get-DnsServerResourceRecord -ZoneName $msdcszone | Where-Object {$_.RecordType -ne "NS" -and $_.RecordType -ne "SOA" -and $_.RecordType -ne "CNAME" -and $_.RecordType -ne "A" }
#Get filtered set of SRV records from _msdcs with upper-case letters
#$dnsrecords = Get-DnsServerResourceRecord -ZoneName $msdcszone | Where-Object {$_.RecordType -ne "NS" -and $_.RecordType -ne "SOA" -and $_.RecordType -ne "CNAME" -and $_.RecordType -ne "A" -and $_.RecordData.DomainName -cmatch '[A-Z]' }

#Initialize the array
$OutputObj = @()

ForEach ($rr in $dnsrecords) {
     $name = $rr.HostName
     $type = $rr.RecordType
     $ttl = $rr.TimeToLive
     $created = $rr.Timestamp
     #$data = $rr.RecordData.DomainName 
     #$data = $rr.RecordData | select DomainName -ExpandProperty DomainName | Out-String
     $data = $rr.RecordData | select DomainName -ExpandProperty DomainName
     $uppercase = $data -cmatch '[A-Z]'   
     
    $OutputObj += New-Object -TypeName PSobject -Property @{
    Name = $name
    Type = $type
    TTL = $ttl
    Created = $created
    Data = $data
    CaseSensitive = $uppercase
    }

   }

#Get Active Directory sites
$sites = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites).Name

#Divide output into generic and site-specific SRV records with upper-case letters 
foreach ($site in $sites) {
$currentpath = "_tcp." + $($site) + "._sites.dc." + $($msdcszone) -replace " ",""
#Write-Host "Records with UPPER-CASE in: " $currentpath.ToLower() "`r`n" -ForegroundColor DarkYellow
Write-Host "Records with UPPER-CASE in" $site "site container `r`n" -ForegroundColor DarkYellow
$OutputObj | where {$_.Name -match $site -and $_.Case -eq $true} | select Name,Data | Format-Table -AutoSize
}
Write-Host "Records with UPPER-CASE in generic containers `r`n" -ForegroundColor DarkYellow
$OutputObj | where {$_.Name -notmatch "._Sites." -and $_.Case -eq $true}| select Name,Data | Format-Table -AutoSize

#EOF