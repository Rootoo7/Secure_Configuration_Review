# Load Active Directory Module
Import-Module ActiveDirectory

# Get the directory from which the script is being executed
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Initialize HTML report
$report = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Security Review</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid black; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h2>Active Directory Security Review</h2>
    <table>
        <tr>
            <th>Observation</th>
            <th>Severity</th>
            <th>Domain Assessed</th>
            <th>Impact</th>
            <th>Recommendation</th>
        </tr>
"@

# Function to add a row to the HTML report
function Add-ReportRow {
    param (
        [string]$observation,
        [string]$severity,
        [string]$domain,
        [string]$impact,
        [string]$recommendation
    )
    $report += "<tr><td>$observation</td><td>$severity</td><td>$domain</td><td>$impact</td><td>$recommendation</td></tr>"
}

# Get domain name
$domain = (Get-ADDomain).DNSRoot

# Check if AD is vulnerable to Kerberoast attacks
$kerberoastVulnerable = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object -Property SamAccountName,ServicePrincipalName
if ($kerberoastVulnerable.Count -gt 0) {
    Add-ReportRow -observation "AD vulnerable to Kerberoast attacks" `
        -severity "High" `
        -domain $domain `
        -impact "Attackers can extract service account hashes and attempt offline password cracking." `
        -recommendation "Use strong, complex passwords for service accounts and periodically change them."
}

# Check for Kerberos account passwords unchanged
$threshold = (Get-Date).AddDays(-365)
$staleAccounts = Get-ADUser -Filter {PasswordLastSet -lt $threshold} -Properties PasswordLastSet
if ($staleAccounts.Count -gt 0) {
    Add-ReportRow -observation "Kerberos account passwords unchanged for over a year" `
        -severity "Medium" `
        -domain $domain `
        -impact "Accounts with stale passwords may be vulnerable to brute force attacks." `
        -recommendation "Enforce a policy to regularly update passwords for all accounts."
}

# Check for Obsolete OS
$obsoleteOS = Get-ADComputer -Filter {OperatingSystem -like "*Windows XP*" -or OperatingSystem -like "*Windows 2003*"}
if ($obsoleteOS.Count -gt 0) {
    Add-ReportRow -observation "Obsolete operating systems in use" `
        -severity "High" `
        -domain $domain `
        -impact "Obsolete systems may have unpatched vulnerabilities and lack support." `
        -recommendation "Upgrade obsolete operating systems to supported versions."
}

# Check if Domain Controllers are outdated
$dcOutdated = Get-ADComputer -Filter {OperatingSystem -like "*Windows 2008*" -or OperatingSystem -like "*Windows 2003*"} -SearchBase "OU=Domain Controllers,DC=example,DC=com"
if ($dcOutdated.Count -gt 0) {
    Add-ReportRow -observation "Outdated domain controllers" `
        -severity "High" `
        -domain $domain `
        -impact "Outdated domain controllers may have unpatched vulnerabilities." `
        -recommendation "Upgrade domain controllers to supported versions."
}

# Check if Non-Admin users can add users to the domain
$nonAdminAddUsers = Get-ADUser -Filter {PrimaryGroupID -ne (Get-ADGroup -Filter {SamAccountName -eq "Domain Admins"}).PrimaryGroupID} -Properties MemberOf | Where-Object {($_.MemberOf -contains (Get-ADGroup -Filter {SamAccountName -eq "Account Operators"}).DistinguishedName)}
if ($nonAdminAddUsers.Count -gt 0) {
    Add-ReportRow -observation "Non-Admin users can add users to the domain" `
        -severity "Medium" `
        -domain $domain `
        -impact "Non-admin users with this privilege can add unauthorized accounts." `
        -recommendation "Restrict user creation privileges to admin users only."
}

# Check if LAPS is installed
try {
    $lapsInstalled = Get-WmiObject -Namespace "root\CIMv2" -Class "Win32_InstalledSoftware" | Where-Object {$_.Name -like "*LAPS*"}
    if ($lapsInstalled) {
        Add-ReportRow -observation "LAPS is installed
