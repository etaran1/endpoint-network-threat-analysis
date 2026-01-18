# Threat Analysis Report

**Case Title:** Suspicious PowerShell + direct-to-IP web access + persistence  
**Analyst:** Emilio Tarango  
**Date:** 2026-01-12  
**Confidence:** Medium  

## Executive Summary
A workstation executed PowerShell spawned from Outlook and made an unusual outbound connection to a direct IP URL, followed by creation of a scheduled task. This pattern is consistent with phishing leading to script execution and establishing persistence.

## Key Findings
- PowerShell executed with suspicious characteristics after email client activity
- Outbound connection to direct IP and unusual URL
- Scheduled task created shortly after, suggesting persistence

## Evidence (Correlated)
| Time | Source | Host | Indicator | Value |
|------|--------|------|----------|-------|
| 19:05 | sysmon | WS-12 | process | powershell.exe (parent outlook.exe) |
| 19:05 | sysmon | WS-12 | network | 198.51.100.77:443 |
| 19:05 | proxy | - | url | https://198.51.100.77/update |
| 19:06 | sysmon | WS-12 | persistence | scheduled_task:UpdateCheck |

## Hypothesis
Likely phishing or malicious attachment triggered script execution. Persistence may allow follow-on access.

## Impact Assessment
- Affected host(s): WS-12
- Risk: persistence, potential credential theft

## Containment / Response Recommendations
- Isolate WS-12 from network
- Collect triage artifacts (running processes, scheduled tasks)
- Block indicator IP and related domains
- Reset credentials for impacted user if compromise confirmed
