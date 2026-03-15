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
     public sources into consolidated, scored output files.

 .DESCRIPTION
     Downloads from the following sources, parses, deduplicates, and writes
     consolidated output to the ../lists/ directory.

     IP sources (each contributes 1 point to an IP's score):
       Source              Feed
       ------------------  --------------------------------------------------
       Feodo Tracker       Botnet C2 servers (Emotet, TrickBot, QakBot, etc.)
       Emerging Threats    Broadly compromised / malicious IPs
       CINS Army           Active threat actors, scanners, brute-force sources
       Binary Defense      Artillery threat intelligence feed
       Greensnow           General attack / scanner IPs
       Tor Exit Nodes      All current Tor exit nodes
       Abuse.ch SSLBL      IPs with malicious SSL certificates / C2 traffic
       ThreatFox           Recent IOCs from the abuse.ch ThreatFox database
       IPsum               Meta-aggregator (~30 feeds); included when score >= 3

     CIDR sources:
       Spamhaus DROP       IP ranges operated by professional crime gangs
       Spamhaus EDROP      Extended DROP — hijacked netblocks

     Domain sources:
       URLhaus             Malware distribution URLs (hostnames extracted)

     Output files:
       lists/ip_blocklist.txt   — All unique IPs (flat, for simple lookups)
       lists/ip_scores.txt      — Scored IPs: "score<TAB>ip", sorted by score desc
       lists/cidr_blocklist.txt — Deduplicated CIDR ranges
       lists/domain_blocklist.txt — Deduplicated hostnames
       lists/metadata.json      — Source stats and last-updated timestamp

     Scoring: an IP's score = the number of independent source lists it appears
     in. Higher scores indicate broader cross-feed consensus on maliciousness.
     The Syncro network monitor uses this score to tier alert severity.

     # TODO: When AbuseIPDB enterprise is purchased, add a bulk blacklist
     # download step here using the API key. The downloaded list can be
     # incorporated as an additional scored source without any Syncro-side
     # changes — just add it as another IP source below.

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

# IP sources — each contributes 1 vote per IP toward the cross-feed score.
# Type key:
#   IP    — plain IPv4 list, one per line, comment lines start with CommentChar
#   SSLBL — abuse.ch SSLBL CSV: "ip,port" rows, comment char #
#   TFOX  — ThreatFox CSV: quoted fields, ioc_value = "ip:port", comment char #
#   IPSUM — stamparm/ipsum tab-separated "ip<TAB>score"; IpsumMinScore filters noise
$IpSources = @(
    [PSCustomObject]@{ Name='Feodo Tracker';   Type='IP';    CommentChar='#'; MinEntries=5; IpsumMinScore=0
        Url='https://feodotracker.abuse.ch/downloads/ipblocklist.txt' }
    [PSCustomObject]@{ Name='Emerging Threats'; Type='IP';   CommentChar='#'; MinEntries=100; IpsumMinScore=0
        Url='https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt' }
    [PSCustomObject]@{ Name='CINS Army';        Type='IP';   CommentChar='#'; MinEntries=100; IpsumMinScore=0
        Url='http://cinsscore.com/list/ci-badguys.txt' }
    [PSCustomObject]@{ Name='Binary Defense';   Type='IP';   CommentChar='#'; MinEntries=100; IpsumMinScore=0
        Url='https://www.binarydefense.com/banlist.txt' }
    [PSCustomObject]@{ Name='Greensnow';        Type='IP';   CommentChar='#'; MinEntries=100; IpsumMinScore=0
        Url='https://blocklist.greensnow.co/greensnow.txt' }
    [PSCustomObject]@{ Name='Tor Exit Nodes';   Type='IP';   CommentChar='#'; MinEntries=50;  IpsumMinScore=0
        Url='https://check.torproject.org/torbulkexitlist' }
    [PSCustomObject]@{ Name='Abuse.ch SSLBL';   Type='SSLBL'; CommentChar='#'; MinEntries=5; IpsumMinScore=0
        Url='https://sslbl.abuse.ch/blacklist/sslipblacklist.txt' }
    [PSCustomObject]@{ Name='ThreatFox';        Type='TFOX'; CommentChar='#'; MinEntries=50;  IpsumMinScore=0
        Url='https://threatfox.abuse.ch/export/csv/ip-port/recent/' }
    [PSCustomObject]@{ Name='IPsum';            Type='IPSUM'; CommentChar='#'; MinEntries=1000; IpsumMinScore=3
        Url='https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt' }
)

$CidrSources = @(
    [PSCustomObject]@{ Name='Spamhaus DROP';  CommentChar=';'; MinEntries=10
        Url='https://www.spamhaus.org/drop/drop.txt' }
    [PSCustomObject]@{ Name='Spamhaus EDROP'; CommentChar=';'; MinEntries=5
        Url='https://www.spamhaus.org/drop/edrop.txt' }
)

$DomainSources = @(
    [PSCustomObject]@{ Name='URLhaus'; CommentChar='#'; MinEntries=100
        Url='https://urlhaus.abuse.ch/downloads/text/' }
)

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message)
    [Console]::WriteLine("[AGGREGATE] $Message")
}

function Invoke-DownloadWithRetry {
    param([string]$Url, [int]$MaxRetries = 3, [int]$RetryDelaySec = 5)
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            return (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30 `
                -UserAgent $UserAgent -ErrorAction Stop).Content
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
    $parts = $Cidr -split '/'; $ip = $null; $prefix = [int]$parts[1]
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return $false }
    return ($prefix -ge 0 -and $prefix -le 32)
}

# Plain IPv4 list — one IP per line, optional inline comment stripped
function Parse-IpLines {
    param([string]$Content, [string]$CommentChar)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith($CommentChar)) { continue }
        $clean = ($line -split $CommentChar)[0].Trim()
        if (Test-IsValidIPv4 -Address $clean) { [void]$set.Add($clean) }
    }
    return $set
}

# abuse.ch SSLBL — CSV rows: "ip,port", comment char #
function Parse-SslblLines {
    param([string]$Content)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $ip = ($line -split ',')[0].Trim()
        if (Test-IsValidIPv4 -Address $ip) { [void]$set.Add($ip) }
    }
    return $set
}

# ThreatFox — quoted CSV, ioc_value field (index 2) = "ip:port", filter ip:port type
function Parse-ThreatFoxLines {
    param([string]$Content)
    $set           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $headerSkipped = $false
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        if (-not $headerSkipped) { $headerSkipped = $true; continue }   # skip CSV header row
        # Split on the inner delimiter between quoted fields: ","
        $parts = $line -split '","'
        if ($parts.Count -lt 4) { continue }
        if ($parts[3] -ne 'ip:port') { continue }                       # ioc_type must be ip:port
        $iocValue = $parts[2].Trim('"')                                  # e.g. "1.2.3.4:8080"
        $ip       = ($iocValue -split ':')[0].Trim()
        if (Test-IsValidIPv4 -Address $ip) { [void]$set.Add($ip) }
    }
    return $set
}

# IPsum — tab-separated "ip<TAB>score"; only include IPs at or above MinScore
function Parse-IpsumLines {
    param([string]$Content, [int]$MinScore)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $parts = $line -split "`t"
        if ($parts.Count -lt 2) { continue }
        $ip = $parts[0].Trim(); $score = 0
        if ([int]::TryParse($parts[1].Trim(), [ref]$score) -and $score -ge $MinScore -and (Test-IsValidIPv4 -Address $ip)) {
            [void]$set.Add($ip)
        }
    }
    return $set
}

function Parse-CidrLines {
    param([string]$Content, [string]$CommentChar)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($Content -split "`n")) {
        $line = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith($CommentChar)) { continue }
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
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith($CommentChar)) { continue }
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

# Adds all IPs from a set into the score map, incrementing each IP's count by 1
function Add-IpsToScoreMap {
    param([hashtable]$ScoreMap, [object]$IpSet, [string]$SourceName)
    foreach ($ip in $IpSet) {
        if ($ScoreMap.ContainsKey($ip)) { $ScoreMap[$ip]++ }
        else                            { $ScoreMap[$ip] = 1 }
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────

# ipScoreMap: IP -> int (count of source lists that include this IP)
$ipScoreMap  = @{}
$allCIDRs    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$allDomains  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$metaSources = [System.Collections.Generic.List[object]]::new()
$exitCode    = 0

# ── IP sources ────────────────────────────────────────────────────────────────
foreach ($source in $IpSources) {
    Write-Log "Processing: $($source.Name)"
    try {
        $content = Invoke-DownloadWithRetry -Url $source.Url

        $parsed = switch ($source.Type) {
            'IP'    { Parse-IpLines      -Content $content -CommentChar $source.CommentChar }
            'SSLBL' { Parse-SslblLines   -Content $content }
            'TFOX'  { Parse-ThreatFoxLines -Content $content }
            'IPSUM' { Parse-IpsumLines   -Content $content -MinScore $source.IpsumMinScore }
        }

        $count = @($parsed).Count
        if ($count -lt $source.MinEntries) {
            Write-Warning "$($source.Name): only $count entries (minimum $($source.MinEntries)). Skipping."
            $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='skipped_too_few'; Count=$count })
            $exitCode = 1
            continue
        }

        Add-IpsToScoreMap -ScoreMap $ipScoreMap -IpSet $parsed -SourceName $source.Name
        Write-Log "$($source.Name): $count IPs added (running total: $($ipScoreMap.Count) unique)."
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='ok'; Count=$count; Url=$source.Url; Type=$source.Type })
    }
    catch {
        Write-Warning "$($source.Name) failed: $($_.Exception.Message)"
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='error'; Error=$_.Exception.Message })
        $exitCode = 1
    }
}

# ── CIDR sources ──────────────────────────────────────────────────────────────
foreach ($source in $CidrSources) {
    Write-Log "Processing: $($source.Name)"
    try {
        $content = Invoke-DownloadWithRetry -Url $source.Url
        $parsed  = Parse-CidrLines -Content $content -CommentChar $source.CommentChar
        $count   = @($parsed).Count
        if ($count -lt $source.MinEntries) {
            Write-Warning "$($source.Name): only $count entries. Skipping."
            $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='skipped_too_few'; Count=$count })
            $exitCode = 1
            continue
        }
        foreach ($e in $parsed) { [void]$allCIDRs.Add($e) }
        Write-Log "$($source.Name): $count CIDRs added."
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='ok'; Count=$count; Url=$source.Url; Type='CIDR' })
    }
    catch {
        Write-Warning "$($source.Name) failed: $($_.Exception.Message)"
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='error'; Error=$_.Exception.Message })
        $exitCode = 1
    }
}

# ── Domain sources ────────────────────────────────────────────────────────────
foreach ($source in $DomainSources) {
    Write-Log "Processing: $($source.Name)"
    try {
        $content = Invoke-DownloadWithRetry -Url $source.Url
        $parsed  = Parse-UrlLines -Content $content -CommentChar $source.CommentChar
        $count   = @($parsed).Count
        if ($count -lt $source.MinEntries) {
            Write-Warning "$($source.Name): only $count entries. Skipping."
            $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='skipped_too_few'; Count=$count })
            $exitCode = 1
            continue
        }
        foreach ($e in $parsed) { [void]$allDomains.Add($e) }
        Write-Log "$($source.Name): $count domains added."
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='ok'; Count=$count; Url=$source.Url; Type='URL' })
    }
    catch {
        Write-Warning "$($source.Name) failed: $($_.Exception.Message)"
        $metaSources.Add([PSCustomObject]@{ Name=$source.Name; Status='error'; Error=$_.Exception.Message })
        $exitCode = 1
    }
}

# ── Write output ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

$timestamp     = Get-Date -Format s
$ipSourceCount = ($IpSources | Measure-Object).Count

# ip_blocklist.txt — flat deduplicated list for simple lookups
$ipPath    = Join-Path $OutputDir 'ip_blocklist.txt'
$sortedIPs = $ipScoreMap.Keys | Sort-Object
Set-Content -Path $ipPath -Encoding UTF8 -Value @"
# Generated by cybertek605/cybertek-threat-intel
# Updated : $timestamp
# Entries : $($ipScoreMap.Count)
# Sources : $ipSourceCount IP feeds (see metadata.json)
"@
Add-Content -Path $ipPath -Value $sortedIPs

# ip_scores.txt — scored list: "score<TAB>ip", descending by score
# Score = number of independent source lists containing this IP (max = $ipSourceCount)
# Used by the Syncro network monitor to tier alert severity:
#   score 1  = Warning  (single-source flagged)
#   score 2+ = Critical (multi-source consensus)
$scorePath   = Join-Path $OutputDir 'ip_scores.txt'
$scoredLines = $ipScoreMap.GetEnumerator() |
    Sort-Object @{Expression={$_.Value}; Descending=$true}, @{Expression={$_.Key}; Descending=$false} |
    ForEach-Object { "$($_.Value)`t$($_.Key)" }
Set-Content -Path $scorePath -Encoding UTF8 -Value @"
# Generated by cybertek605/cybertek-threat-intel
# Updated    : $timestamp
# Format     : score<TAB>ip_address
# Score      : number of independent source lists containing this IP (max $ipSourceCount)
# Severity   : score=1 -> Warning | score>=2 -> Critical
# Entries    : $($ipScoreMap.Count)
"@
Add-Content -Path $scorePath -Value $scoredLines

# cidr_blocklist.txt
$cidrPath = Join-Path $OutputDir 'cidr_blocklist.txt'
Set-Content -Path $cidrPath -Encoding UTF8 -Value @"
# Generated by cybertek605/cybertek-threat-intel
# Updated : $timestamp
# Entries : $($allCIDRs.Count)
"@
Add-Content -Path $cidrPath -Value ($allCIDRs | Sort-Object)

# domain_blocklist.txt
$domainPath = Join-Path $OutputDir 'domain_blocklist.txt'
Set-Content -Path $domainPath -Encoding UTF8 -Value @"
# Generated by cybertek605/cybertek-threat-intel
# Updated : $timestamp
# Entries : $($allDomains.Count)
"@
Add-Content -Path $domainPath -Value ($allDomains | Sort-Object)

# metadata.json
$maxScore = if ($ipScoreMap.Count -gt 0) { ($ipScoreMap.Values | Measure-Object -Maximum).Maximum } else { 0 }
([PSCustomObject]@{
    UpdatedAt         = $timestamp
    TotalUniqueIPs    = $ipScoreMap.Count
    TotalCIDRs        = $allCIDRs.Count
    TotalDomains      = $allDomains.Count
    MaxIpScore        = $maxScore
    IpSourceCount     = $ipSourceCount
    Sources           = $metaSources
} | ConvertTo-Json -Depth 5) | Set-Content -Path (Join-Path $OutputDir 'metadata.json') -Encoding UTF8

Write-Log "Complete — Unique IPs: $($ipScoreMap.Count) (max score: $maxScore) | CIDRs: $($allCIDRs.Count) | Domains: $($allDomains.Count)"
exit $exitCode
