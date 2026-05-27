<#
.SYNOPSIS
    Passive wireless baseline and rogue AP indicator checklist for authorized onsite validation.

.DESCRIPTION
    Collects local wireless, network, and adapter state from a Windows laptop and writes
    Markdown and JSON reports for baseline comparison and drift detection.
#>

param(
    [string]$AdapterPattern = 'AWUS1900|8814AU|Wireless LAN|Wi-Fi',
    [string]$OutputDir = (Get-Location).Path,
    [switch]$PingGateway,
    [string]$ExpectedApInventoryPath = (Join-Path (Get-Location).Path 'expected-aps.json')
)

$ErrorActionPreference = 'Stop'

function New-CheckResult {
    param(
        [string]$Name,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,
        [string]$Details
    )

    [pscustomobject]@{
        Check   = $Name
        Status  = $Status
        Details = $Details
    }
}

function Add-Check {
    param(
        [string]$Name,
        [scriptblock]$Script
    )

    try {
        & $Script
    }
    catch {
        New-CheckResult -Name $Name -Status 'FAIL' -Details $_.Exception.Message
    }
}

function Get-FirstMatchValue {
    param(
        [string[]]$Lines,
        [string]$Pattern
    )

    foreach ($line in $Lines) {
        if ($line -match $Pattern) {
            return $Matches[1].Trim()
        }
    }

    return $null
}

function Get-WlanNetworkInventory {
    param(
        [string[]]$Lines
    )

    $inventory = New-Object System.Collections.Generic.List[object]
    $current = $null
    $currentBssid = $null

    foreach ($line in $Lines) {
        if ($line -match '^\s*SSID\s+\d+\s*:\s*(.+)$') {
            if ($current) {
                $inventory.Add([pscustomobject]$current)
            }

            $current = [ordered]@{
                SSID   = $Matches[1].Trim()
                Auth   = $null
                Cipher = $null
                BSSIDs = New-Object System.Collections.Generic.List[object]
            }
            $currentBssid = $null
            continue
        }

        if (-not $current) {
            continue
        }

        if ($line -match '^\s*Authentication\s*:\s*(.+)$') {
            $current.Auth = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*(?:Cipher|Encryption)\s*:\s*(.+)$') {
            $current.Cipher = $Matches[1].Trim()
            continue
        }

        if ($line -match '^\s*BSSID\s+\d+\s*:\s*(.+)$') {
            $currentBssid = [ordered]@{
                BSSID   = $Matches[1].Trim()
                Signal  = $null
                Radio   = $null
                Channel = $null
            }

            $current.BSSIDs.Add([pscustomobject]$currentBssid)
            continue
        }

        if ($currentBssid) {
            if ($line -match '^\s*Signal\s*:\s*(.+)$') {
                $currentBssid.Signal = $Matches[1].Trim()
                continue
            }

            if ($line -match '^\s*Radio type\s*:\s*(.+)$') {
                $currentBssid.Radio = $Matches[1].Trim()
                continue
            }

            if ($line -match '^\s*Channel\s*:\s*(.+)$') {
                $currentBssid.Channel = $Matches[1].Trim()
                continue
            }
        }
    }

    if ($current) {
        $inventory.Add([pscustomobject]$current)
    }

    return $inventory
}

function Normalize-MacAddress {
    param([string]$Value)

    if (-not $Value) {
        return $null
    }

    return (($Value -replace '[^0-9A-Fa-f]', '')).ToUpperInvariant()
}

function Test-AllowedBssid {
    param(
        [string]$CurrentBssid,
        [object]$ExpectedEntry
    )

    if (-not $CurrentBssid -or -not $ExpectedEntry) {
        return $false
    }

    $normalizedCurrent = Normalize-MacAddress $CurrentBssid
    $expectedList = @()

    if ($ExpectedEntry.PSObject.Properties.Name -contains 'BSSIDs' -and $ExpectedEntry.BSSIDs) {
        $expectedList = @($ExpectedEntry.BSSIDs)
    }
    elseif ($ExpectedEntry.PSObject.Properties.Name -contains 'Bssid' -and $ExpectedEntry.Bssid) {
        $expectedList = @($ExpectedEntry.Bssid)
    }
    elseif ($ExpectedEntry.PSObject.Properties.Name -contains 'BSSID' -and $ExpectedEntry.BSSID) {
        $expectedList = @($ExpectedEntry.BSSID)
    }

    foreach ($candidate in $expectedList) {
        if ($normalizedCurrent -eq (Normalize-MacAddress $candidate)) {
            return $true
        }
    }

    return $false
}

function Test-ExpectedApInventory {
    param(
        [object]$Inventory
    )

    if (-not $Inventory) {
        return $false
    }

    foreach ($entry in @($Inventory)) {
        if (-not ($entry.PSObject.Properties.Name -contains 'SSID') -or -not $entry.SSID) {
            return $false
        }

        if ($entry.PSObject.Properties.Name -contains 'BSSIDs' -and $entry.BSSIDs) {
            foreach ($bssid in @($entry.BSSIDs)) {
                if (-not (Normalize-MacAddress $bssid)) {
                    return $false
                }
            }
        }
    }

    return $true
}

$timestamp = Get-Date
$reportBase = Join-Path $OutputDir ("awus1900-checklist-{0:yyyyMMdd-HHmmss}" -f $timestamp)
$jsonPath = "$reportBase.json"
$mdPath = "$reportBase.md"

$checks = New-Object System.Collections.Generic.List[object]

$wlanService = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
$checks.Add((Add-Check -Name 'WLAN service running' -Script {
    if (-not $wlanService) {
        New-CheckResult -Name 'WLAN service running' -Status 'FAIL' -Details 'WlanSvc not found.'
        return
    }

    if ($wlanService.Status -eq 'Running') {
        New-CheckResult -Name 'WLAN service running' -Status 'PASS' -Details 'WlanSvc is running.'
    }
    else {
        New-CheckResult -Name 'WLAN service running' -Status 'FAIL' -Details ("WlanSvc status is {0}." -f $wlanService.Status)
    }
}))

$adapterQueryError = $null
try {
    $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object {
        $_.InterfaceDescription -match $AdapterPattern -or $_.Name -match $AdapterPattern
    }
}
catch {
    $adapterQueryError = $_.Exception.Message
    $adapters = @()
}

$checks.Add((Add-Check -Name 'AWUS adapter present' -Script {
    if ($adapters.Count -gt 0) {
        $names = $adapters | ForEach-Object { "$($_.Name) [$($_.Status)]" }
        New-CheckResult -Name 'AWUS adapter present' -Status 'PASS' -Details ($names -join '; ')
    }
    else {
        if ($adapterQueryError) {
            New-CheckResult -Name 'AWUS adapter present' -Status 'WARN' -Details "Could not query adapters: $adapterQueryError"
        }
        else {
            New-CheckResult -Name 'AWUS adapter present' -Status 'FAIL' -Details "No adapter matched pattern '$AdapterPattern'."
        }
    }
}))

$primaryAdapter = $adapters | Select-Object -First 1

$checks.Add((Add-Check -Name 'Adapter enabled' -Script {
    if (-not $primaryAdapter) {
        New-CheckResult -Name 'Adapter enabled' -Status 'FAIL' -Details 'No matching adapter to inspect.'
        return
    }

    if ($primaryAdapter.Status -eq 'Up') {
        New-CheckResult -Name 'Adapter enabled' -Status 'PASS' -Details ("{0} is Up." -f $primaryAdapter.Name)
    }
    else {
        New-CheckResult -Name 'Adapter enabled' -Status 'WARN' -Details ("{0} status is {1}." -f $primaryAdapter.Name, $primaryAdapter.Status)
    }
}))

$checks.Add((Add-Check -Name 'Driver details' -Script {
    if (-not $primaryAdapter) {
        New-CheckResult -Name 'Driver details' -Status 'FAIL' -Details 'No matching adapter to inspect.'
        return
    }

    $driver = Get-CimInstance Win32_PnPSignedDriver |
        Where-Object { $_.DeviceName -eq $primaryAdapter.InterfaceDescription } |
        Select-Object -First 1

    if ($driver) {
        $details = "Provider: $($driver.DriverProviderName); Version: $($driver.DriverVersion); Date: $($driver.DriverDate)"
        New-CheckResult -Name 'Driver details' -Status 'PASS' -Details $details
    }
    else {
        New-CheckResult -Name 'Driver details' -Status 'WARN' -Details 'Driver metadata not found for the selected adapter.'
    }
}))

$checks.Add((Add-Check -Name 'IP configuration' -Script {
    if (-not $primaryAdapter) {
        New-CheckResult -Name 'IP configuration' -Status 'FAIL' -Details 'No matching adapter to inspect.'
        return
    }

    $ip = Get-NetIPConfiguration -InterfaceIndex $primaryAdapter.ifIndex -ErrorAction SilentlyContinue
    if (-not $ip) {
        New-CheckResult -Name 'IP configuration' -Status 'WARN' -Details 'No IP configuration available for the adapter.'
        return
    }

    $ipv4 = $ip.IPv4Address | Select-Object -First 1
    $gateway = $ip.IPv4DefaultGateway | Select-Object -First 1
    $dns = ($ip.DNSServer.ServerAddresses -join ', ')
    $details = @(
        "IPv4: $($ipv4.IPAddress)",
        "Prefix: $($ipv4.PrefixLength)",
        "Gateway: $($gateway.NextHop)",
        "DNS: $dns"
    ) -join '; '

    New-CheckResult -Name 'IP configuration' -Status 'PASS' -Details $details
}))

$checks.Add((Add-Check -Name 'Route table' -Script {
    if (-not $primaryAdapter) {
        New-CheckResult -Name 'Route table' -Status 'FAIL' -Details 'No matching adapter to inspect.'
        return
    }

    $route = Get-NetRoute -InterfaceIndex $primaryAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric |
        Select-Object -First 5

    if ($route) {
        $summary = $route | ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop) metric $($_.RouteMetric)" }
        New-CheckResult -Name 'Route table' -Status 'PASS' -Details ($summary -join '; ')
    }
    else {
        New-CheckResult -Name 'Route table' -Status 'WARN' -Details 'No IPv4 routes returned for the adapter.'
    }
}))

$checks.Add((Add-Check -Name 'Wireless interface state' -Script {
    $netsh = netsh wlan show interfaces 2>$null
    if (-not $netsh) {
        New-CheckResult -Name 'Wireless interface state' -Status 'WARN' -Details 'No wireless interface data returned by netsh.'
        return
    }

    $lines = $netsh -split "`r?`n"
    $ssid = Get-FirstMatchValue -Lines $lines -Pattern '^\s*SSID\s*:\s*(.+)$'
    $bssid = Get-FirstMatchValue -Lines $lines -Pattern '^\s*BSSID\s*:\s*(.+)$'
    $state = Get-FirstMatchValue -Lines $lines -Pattern '^\s*State\s*:\s*(.+)$'
    $radio = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Radio type\s*:\s*(.+)$'
    $auth = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Authentication\s*:\s*(.+)$'
    $cipher = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Cipher\s*:\s*(.+)$'
    $channel = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Channel\s*:\s*(.+)$'
    $signal = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Signal\s*:\s*(.+)$'

    $details = @(
        "State: $state",
        "SSID: $ssid",
        "BSSID: $bssid",
        "Radio: $radio",
        "Auth: $auth",
        "Cipher: $cipher",
        "Channel: $channel",
        "Signal: $signal"
    ) -join '; '

    if ($state -and $state -match 'connected') {
        New-CheckResult -Name 'Wireless interface state' -Status 'PASS' -Details $details
    }
    else {
        New-CheckResult -Name 'Wireless interface state' -Status 'WARN' -Details $details
    }
}))

$checks.Add((Add-Check -Name 'Wireless security posture' -Script {
    $netsh = netsh wlan show interfaces 2>$null
    if (-not $netsh) {
        New-CheckResult -Name 'Wireless security posture' -Status 'WARN' -Details 'No wireless interface data returned by netsh.'
        return
    }

    $lines = $netsh -split "`r?`n"
    $auth = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Authentication\s*:\s*(.+)$'
    $cipher = Get-FirstMatchValue -Lines $lines -Pattern '^\s*Cipher\s*:\s*(.+)$'

    if (-not $auth -and -not $cipher) {
        New-CheckResult -Name 'Wireless security posture' -Status 'WARN' -Details 'Could not parse authentication and cipher fields.'
        return
    }

    $pass = $false
    if ($auth -match 'WPA3' -or $auth -match 'WPA2') {
        $pass = $true
    }

    $details = "Authentication: $auth; Cipher: $cipher"
    if ($pass) {
        New-CheckResult -Name 'Wireless security posture' -Status 'PASS' -Details $details
    }
    else {
        New-CheckResult -Name 'Wireless security posture' -Status 'WARN' -Details $details
    }
}))

$checks.Add((Add-Check -Name 'Visible SSIDs' -Script {
    $netsh = netsh wlan show networks mode=bssid 2>$null
    if (-not $netsh) {
        New-CheckResult -Name 'Visible SSIDs' -Status 'WARN' -Details 'No visible network list returned by netsh.'
        return
    }

    $ssidCount = ([regex]::Matches($netsh, '^\s*SSID\s+\d+\s*:', [System.Text.RegularExpressions.RegexOptions]::Multiline)).Count
    New-CheckResult -Name 'Visible SSIDs' -Status 'INFO' -Details ("Visible SSID entries: {0}" -f $ssidCount)
}))

$checks.Add((Add-Check -Name 'Possible rogue AP indicators' -Script {
    $ifaceNetsh = netsh wlan show interfaces 2>$null
    $scanNetsh = netsh wlan show networks mode=bssid 2>$null

    if (-not $ifaceNetsh -or -not $scanNetsh) {
        New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details 'Wireless scan data unavailable.'
        return
    }

    $ifaceLines = $ifaceNetsh -split "`r?`n"
    $scanLines = $scanNetsh -split "`r?`n"
    $ssid = Get-FirstMatchValue -Lines $ifaceLines -Pattern '^\s*SSID\s*:\s*(.+)$'
    $currentBssid = Get-FirstMatchValue -Lines $ifaceLines -Pattern '^\s*BSSID\s*:\s*(.+)$'
    $auth = Get-FirstMatchValue -Lines $ifaceLines -Pattern '^\s*Authentication\s*:\s*(.+)$'
    $cipher = Get-FirstMatchValue -Lines $ifaceLines -Pattern '^\s*Cipher\s*:\s*(.+)$'

    if (-not $ssid) {
        New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details 'Could not determine the connected SSID.'
        return
    }

    $networks = Get-WlanNetworkInventory -Lines $scanLines
    $match = $networks | Where-Object { $_.SSID -eq $ssid } | Select-Object -First 1
    $inventory = $null
    $inventoryLoaded = $false

    if (Test-Path -LiteralPath $ExpectedApInventoryPath) {
        try {
            $inventory = Get-Content -LiteralPath $ExpectedApInventoryPath -Raw | ConvertFrom-Json
            $inventoryLoaded = $true
        }
        catch {
            New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details ("Could not load inventory '{0}': {1}" -f $ExpectedApInventoryPath, $_.Exception.Message)
            return
        }
    }

    if (-not $match) {
        New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details ("Connected SSID '{0}' was not found in the scan list." -f $ssid)
        return
    }

    $bssidCount = @($match.BSSIDs).Count
    $signals = @($match.BSSIDs | ForEach-Object { "$($_.BSSID) [$($_.Signal)]" })
    $details = "SSID: $ssid; Current BSSID: $currentBssid; BSSIDs seen: $bssidCount; Auth: $($match.Auth); Cipher: $($match.Cipher); APs: $($signals -join '; ')"

    if ($inventoryLoaded) {
        if (-not (Test-ExpectedApInventory -Inventory $inventory)) {
            New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details ("Inventory at '{0}' is not valid or complete." -f $ExpectedApInventoryPath)
            return
        }

        $expectedEntry = $inventory | Where-Object { $_.SSID -eq $ssid } | Select-Object -First 1

        if (-not $expectedEntry) {
            New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details ("SSID '{0}' is not present in expected-aps.json." -f $ssid)
            return
        }

        $expectedAuth = $expectedEntry.Auth
        $expectedCipher = $expectedEntry.Cipher
        $bssidAllowed = Test-AllowedBssid -CurrentBssid $currentBssid -ExpectedEntry $expectedEntry
        $authMatch = -not $expectedAuth -or ($auth -and $auth -eq $expectedAuth)
        $cipherMatch = -not $expectedCipher -or ($cipher -and $cipher -eq $expectedCipher)

        if ($bssidAllowed -and $authMatch -and $cipherMatch) {
            New-CheckResult -Name 'Possible rogue AP indicators' -Status 'PASS' -Details ("Approved AP matched inventory. {0}" -f $details)
        }
        else {
            $reasons = @()
            if (-not $bssidAllowed) { $reasons += 'BSSID not in allowlist' }
            if (-not $authMatch) { $reasons += "Auth mismatch expected '$expectedAuth'" }
            if (-not $cipherMatch) { $reasons += "Cipher mismatch expected '$expectedCipher'" }
            New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details ("Inventory mismatch: {0}; {1}" -f ($reasons -join '; '), $details)
        }
    }
    else {
        New-CheckResult -Name 'Possible rogue AP indicators' -Status 'WARN' -Details ("No approved inventory configured; {0}" -f $details)
    }
}))

if ($PingGateway) {
    $checks.Add((Add-Check -Name 'Gateway reachability' -Script {
        if (-not $primaryAdapter) {
            New-CheckResult -Name 'Gateway reachability' -Status 'FAIL' -Details 'No matching adapter to inspect.'
            return
        }

        $ip = Get-NetIPConfiguration -InterfaceIndex $primaryAdapter.ifIndex -ErrorAction SilentlyContinue
        $gateway = $ip.IPv4DefaultGateway | Select-Object -First 1

        if (-not $gateway) {
            New-CheckResult -Name 'Gateway reachability' -Status 'WARN' -Details 'No IPv4 gateway detected.'
            return
        }

        if (Test-Connection -ComputerName $gateway.NextHop -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            New-CheckResult -Name 'Gateway reachability' -Status 'PASS' -Details ("Ping to {0} succeeded." -f $gateway.NextHop)
        }
        else {
            New-CheckResult -Name 'Gateway reachability' -Status 'WARN' -Details ("Ping to {0} did not reply." -f $gateway.NextHop)
        }
    }))
}

$results = $checks.ToArray()

$report = [pscustomobject]@{
    Timestamp     = $timestamp.ToString('o')
    Hostname      = $env:COMPUTERNAME
    Username      = $env:USERNAME
    ScriptPath    = $PSCommandPath
    ScriptSha256  = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    Results       = $results
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$mdLines = @()
$mdLines += "# AWUS1900 Checklist"
$mdLines += ""
$mdLines += "- Timestamp: $($timestamp.ToString('u'))"
$mdLines += "- Hostname: $($env:COMPUTERNAME)"
$mdLines += "- Adapter pattern: $AdapterPattern"
$mdLines += ""
$mdLines += "| Check | Status | Details |"
$mdLines += "| --- | --- | --- |"
foreach ($result in $results) {
    $details = ($result.Details -replace '\|', '\|')
    $mdLines += "| $($result.Check) | $($result.Status) | $details |"
}

$mdLines | Set-Content -LiteralPath $mdPath -Encoding UTF8

$manifest = [pscustomobject]@{
    Timestamp    = $timestamp.ToString('o')
    Hostname     = $env:COMPUTERNAME
    Username     = $env:USERNAME
    ScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    Files        = @(
        [pscustomobject]@{
            Path   = $jsonPath
            Sha256 = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash
        },
        [pscustomobject]@{
            Path   = $mdPath
            Sha256 = (Get-FileHash -LiteralPath $mdPath -Algorithm SHA256).Hash
        }
    )
}

if (Test-Path -LiteralPath $ExpectedApInventoryPath) {
    $manifest | Add-Member -NotePropertyName ExpectedInventoryPath -NotePropertyValue $ExpectedApInventoryPath
    $manifest | Add-Member -NotePropertyName ExpectedInventorySha256 -NotePropertyValue (Get-FileHash -LiteralPath $ExpectedApInventoryPath -Algorithm SHA256).Hash
}

$manifestPath = "$reportBase.manifest.json"
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Checklist complete."
Write-Host "Markdown: $mdPath"
Write-Host "JSON:     $jsonPath"
Write-Host "Manifest: $manifestPath"
Write-Host ""

$passCount = @($results | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = @($results | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = @($results | Where-Object { $_.Status -eq 'FAIL' }).Count
$infoCount = @($results | Where-Object { $_.Status -eq 'INFO' }).Count
Write-Host ("Summary: {0} PASS, {1} WARN, {2} FAIL, {3} INFO" -f $passCount, $warnCount, $failCount, $infoCount)
Write-Host ""

foreach ($result in $results) {
    Write-Host ("[{0}] {1} - {2}" -f $result.Status, $result.Check, $result.Details)
}
