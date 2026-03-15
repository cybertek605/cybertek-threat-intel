#requires -Version 5.1
<#
    ______      __              __       __
   / ____/_  __/ /_  ___  _____/ /____  / /__
  / /   / / / / __ \/ _ \/ ___/ __/ _ \/ //_/
 / /___/ /_/ / /_/ /  __/ /  / /_/  __/ ,<
 \____/\__, /_.___/\___/_/   \__/\___/_/|_|
      /____/

 .SYNOPSIS
     Aggregates and deduplicates threat intelligence blocklists from multiple
     public sources into consolidated output files.

 .DESCRIPTION
     Downloads from the following sources, parses, deduplicates, and writes
     consolidated output to the ../lists/ directory:

       Source              Type    Feed
       ------------------  ------  --------------------------------------------------
       Feodo Tracker       IPs     Botnet C2 servers (Emotet, TrickBot, QakBot, etc.)
       Emerging Threats    IPs     Broadly compromised / malicious IPs
       Spamhaus DROP       CIDRs   IP ranges operated by professional spam/crime gangs
       Spamhaus EDROP      CIDRs   Extended DROP — hijacked netblocks
       URLhaus             Domains Malware distribution URLs (hostnames extracted)

     Output files:
       lists/ip_blocklist.txt     — Deduplicated IPv4 addresses
       lists/cidr_blocklist.txt   — Deduplicated CIDR ranges
       lists/domain_blocklist.txt — Deduplicated hostnames
       lists/metadata.json        — Source stats and last-updated timestamp

     NOTE: Spamhaus DROP/EDROP are free for non-commercial use. Review
     https://www.spamhaus.org/organization/dnsblusage/ for your use case.

 .NOTES
     Script Name : aggregate.ps1
     Author      : Cybertek
     Version     : 2026-03-15
     Run Context : GitHub Actions (pwsh on ubuntu-latest), daily cron
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$OutputDir = Join-Path $PSScriptRoot '..' 'lists'
$UserAgent = 'cybertek605/cybertek-threat-intel threat-intel-aggregator/1.0'

$Sources = @(
    [PSCustomObject]@{
        Name       = 'Feodo Tracker'
        Url        = 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
        Type       = 'IP'
        MinEntries = 100
        CommentChar = '#'
    }
    [PSCustomObject]@{
        Name       = 'Emerging Threats'
        Url        = 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
        Type       = 'IP'
        MinEntries = 100
        CommentChar = '#'
    }
    [PSCustomObject]@{
        Name       = 'Spamhaus DROP'
        Url        = 'https://www.spamhaus.org/drop/drop.txt'
        Type       = 'CIDR'
        MinEntries = 10
        CommentChar = ';'
    }
    [PSCustomObject]@{
        Name       = 'Spamhaus EDROP'
        Url        = 'https://www.spamhaus.org/drop/edrop.txt'
        Type       = 'CIDR'
        MinEntries = 5
        CommentChar = ';'
    }
    [PSCustomObject]@{
        Name       = 'URLhaus'
        Url        = 'https://urlhaus.abuse.ch/downloads/text/'
        Type       = 'URL'
        MinEntries = 100
        CommentChar = '#'
    }
)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message)
    [Console]::WriteLine("[AGGREGATE] $Message")
}

function Invoke-DownloadWithRetry {
    param(
        [string]$Url,
        [string]$UserAgent,
        [int]$MaxRetries    = 3,
        [int]$RetryDelaySec = 5
    )
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30 `
                -UserAgent $UserAgent -ErrorAction Stop
            return $response.Content
        }
        catch {
            Write-Warning "Attempt $attempt/$MaxRetries failed for ${Url}: $($_.Exception.Message)"
            if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelaySec }
        }
    }
    throw "All $MaxRetries download attempts failed for $Url"
}

function Test-IsValidIPv4 {
    param([string]$Address)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Address.Trim(), [ref]$ip)) {
        return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    }
    return $false
}

function Test-IsValidCidr {
    param([string]$Cidr)
    if ($Cidr -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') { return $false }
    $parts  = $Cidr -split '/'
    $ip     = $null
    $prefix = [int]$parts[1]
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return $false }
    return ($prefix -ge 0 -and $prefix -le 32)
}

function Parse-IpLines {
    param([string]$Content, [string]$CommentChar)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line))    { continue }
        if ($line.StartsWith($CommentChar))         { continue }
        $clean = ($line -split $CommentChar)[0].Trim()
        if (Test-IsValidIPv4 -Address $clean) { [void]$set.Add($clean) }
    }
    return $set
}

function Parse-CidrLines {
    param([string]$Content, [string]$CommentChar)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line))    { continue }
        if ($line.StartsWith($CommentChar))         { continue }
        # Strip inline comment/reference (Spamhaus: "1.2.3.0/24 ; SBL123")
        $clean = ($line -split ';')[0].Trim()
        if (Test-IsValidCidr -Cidr $clean) { [void]$set.Add($clean) }
    }
    return $set
}

function Parse-UrlLines {
    param([string]$Content, [string]$CommentChar)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith($CommentChar))      { continue }
        try {
            $uri = [System.Uri]$line
            if (-not [string]::IsNullOrWhiteSpace($uri.Host)) {
                [void]$set.Add($uri.Host.ToLowerInvariant().TrimEnd('.'))
            }
        }
        catch {}
    }
    return $set
}

# ── Main ──────────────────────────────────────────────────────────────────────

$allIPs     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allCIDRs   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

$metaSources = [System.Collections.Generic.List[object]]::new()
$exitCode    = 0

foreach ($source in $Sources) {
    Write-Log "Processing: $($source.Name)"
    try {
        $content = Invoke-DownloadWithRetry -Url $source.Url -UserAgent $UserAgent

        $parsed = switch ($source.Type) {
            'IP'   { Parse-IpLines   -Content $content -CommentChar $source.CommentChar }
            'CIDR' { Parse-CidrLines -Content $content -CommentChar $source.CommentChar }
            'URL'  { Parse-UrlLines  -Content $content -CommentChar $source.CommentChar }
        }

        $count = $parsed.Count
        if ($count -lt $source.MinEntries) {
            Write-Warning "$($source.Name): only $count entries parsed (minimum $($source.MinEntries) expected). Skipping."
            $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='skipped_too_few'; Count=$count })
            $exitCode = 1
            continue
        }

        switch ($source.Type) {
            'IP'   { foreach ($e in $parsed) { [void]$allIPs.Add($e) } }
            'CIDR' { foreach ($e in $parsed) { [void]$allCIDRs.Add($e) } }
            'URL'  { foreach ($e in $parsed) { [void]$allDomains.Add($e) } }
        }

        Write-Log "$($source.Name): $count entries added."
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='ok'; Count=$count; Url=$source.Url })
    }
    catch {
        Write-Warning "$($source.Name) failed: $($_.Exception.Message)"
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='error'; Error=$_.Exception.Message })
        $exitCode = 1
    }
}

# Write output files
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$timestamp  = Get-Date -Format s
$fileHeader = "# Generated by cybertek605/cybertek-threat-intel`n# Updated : $timestamp`n# Entries : {0}`n"

$ipPath     = Join-Path $OutputDir 'ip_blocklist.txt'
$cidrPath   = Join-Path $OutputDir 'cidr_blocklist.txt'
$domainPath = Join-Path $OutputDir 'domain_blocklist.txt'
$metaPath   = Join-Path $OutputDir 'metadata.json'

Set-Content -Path $ipPath     -Value ($fileHeader -f $allIPs.Count)     -Encoding UTF8
Add-Content -Path $ipPath     -Value ($allIPs     | Sort-Object)

Set-Content -Path $cidrPath   -Value ($fileHeader -f $allCIDRs.Count)   -Encoding UTF8
Add-Content -Path $cidrPath   -Value ($allCIDRs   | Sort-Object)

Set-Content -Path $domainPath -Value ($fileHeader -f $allDomains.Count) -Encoding UTF8
Add-Content -Path $domainPath -Value ($allDomains | Sort-Object)

([PSCustomObject]@{
    UpdatedAt    = $timestamp
    TotalIPs     = $allIPs.Count
    TotalCIDRs   = $allCIDRs.Count
    TotalDomains = $allDomains.Count
    Sources      = $metaSources
} | ConvertTo-Json -Depth 5) | Set-Content -Path $metaPath -Encoding UTF8

Write-Log "Complete — IPs: $($allIPs.Count) | CIDRs: $($allCIDRs.Count) | Domains: $($allDomains.Count)"
exit $exitCode
