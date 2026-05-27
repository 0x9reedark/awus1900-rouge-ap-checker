# Wireless Baseline Audit for Onsite Validation

This repository contains a passive PowerShell checklist for validating an office wireless environment from an authorized Windows laptop. It is designed for onsite readiness checks, drift detection, and evidence capture in controlled environments such as fintech or PCI-aligned deployments.

## Purpose

The goal is to answer a narrow set of questions with repeatable output:

- Is the wireless adapter present and usable?
- What SSID and BSSID is the laptop connected to?
- What IP, DNS, and route state did the device receive?
- Is the wireless security posture what we expect?
- Are there signs that the connected AP is not part of the approved inventory?

This is a validation tool, not an attack tool. It is intentionally passive and avoids intrusive probing.

## What It Checks

- WLAN service status
- Adapter presence and link state
- Driver metadata
- IP configuration
- Route table
- Current wireless interface state
- Wireless security posture
- Nearby SSID visibility
- Rogue AP / evil twin indicators against an optional allowlist
- Optional gateway reachability

## Files

- `awus1900-checklist.ps1` - main checklist runner
- `expected-aps.example.json` - sample approved AP inventory
- `README.md` - project documentation

## Quick Start

Run the checklist:

```powershell
.\awus1900-checklist.ps1
```

Add a gateway reachability check:

```powershell
.\awus1900-checklist.ps1 -PingGateway
```

Point it at an approved AP inventory:

```powershell
.\awus1900-checklist.ps1 -ExpectedApInventoryPath .\expected-aps.json
```

If your adapter name does not match the default pattern, narrow it:

```powershell
.\awus1900-checklist.ps1 -AdapterPattern '8814AU'
```

## Output

Each run writes:

- a Markdown report for humans
- a JSON report for automation or archival

The filenames are timestamped and written to the current directory unless `-OutputDir` is set.

## Approved AP Inventory

The rogue AP check becomes more useful when you maintain a small approved inventory.

Start from `expected-aps.example.json`, then create `expected-aps.json` with the SSIDs, expected auth mode, expected cipher, and known BSSIDs for your environment.

Example:

```json
[
  {
    "SSID": "Office-Corp",
    "Auth": "WPA2-Enterprise",
    "Cipher": "CCMP",
    "BSSIDs": [
      "00:11:22:33:44:55",
      "00:11:22:33:44:66"
    ]
  }
]
```

## Interpretation

- `PASS` means the check matched expected conditions.
- `WARN` means the check found something suspicious, incomplete, or not yet verifiable.
- `FAIL` means the required local state was missing or the check could not confirm a basic prerequisite.
- `INFO` is descriptive context.

For the AP check specifically:

- `PASS` means the observed AP matched the allowlist.
- `WARN` means the SSID/BSSID/security combination was unexpected or could not be confirmed.

## Limitations

This repository can flag suspicious wireless patterns, but it cannot prove an evil twin on its own. In a real office with multiple legitimate APs, multiple BSSIDs for the same SSID can be normal.

For a stronger control, keep a current approved inventory and compare against it during onsite validation.

## Safety Notes

- Run this only on systems and networks you are authorized to assess.
- Keep the scope limited to validation, evidence capture, and drift detection.
- Do not use it to probe or disrupt third-party systems.

## Suggested Workflow

1. Bring up the test laptop onsite.
2. Connect through the authorized office Wi-Fi.
3. Run the checklist.
4. Review the report for mismatches or drift.
5. Compare against the last known good baseline.
6. Fix configuration issues before the environment is treated as trusted.

