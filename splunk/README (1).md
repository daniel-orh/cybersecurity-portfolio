# Splunk

This folder documents my hands on practice with **Splunk Enterprise**, a SIEM (Security Information and Event Management) platform widely used in Security Operations Centres to collect, search and alert on log data.

The aim is to build practical skills in log analysis and threat detection that a SOC Analyst uses day to day: ingesting data, writing searches in SPL (Search Processing Language), and turning suspicious activity into clear findings.

## Lab Environment

| Component | Detail |
|---|---|
| Host | Windows 11 Pro virtual machine running in VMware Workstation |
| SIEM | Splunk Enterprise 10.6 (60 day trial, converting to Splunk Free) |
| Data sources | Windows Event Logs: Application, Security and System |
| Index | `windows` (a dedicated index rather than the default `main`) |

Running Splunk inside a VM keeps the lab isolated from my main machine and lets me safely generate and investigate suspicious activity.

## Sessions

| Session | Focus | Write-up |
|---|---|---|
| 1 | Installing Splunk, ingesting Windows event logs, and detecting failed logon attempts | [splunk_session_1.md](splunk_session_1.md) |

## Windows Event IDs Reference

Key event codes I have worked with or plan to monitor:

| Event ID | Meaning | Why it matters |
|---|---|---|
| 4624 | Successful logon | Baseline of normal activity; unusual times or logon types can indicate compromise |
| 4625 | Failed logon | Repeated failures can indicate brute force or password spraying |
| 4672 | Special privileges assigned to new logon | Shows administrator logons, which attackers aim for |
| 4688 | New process created | Reveals what programs ran, useful for spotting malicious commands |
| 4720 | User account created | Attackers often create accounts for persistence |

## Planned Next Steps

* Install **Sysmon** to capture far more detailed endpoint activity
* Attack the Windows VM from a **Kali Linux** VM and investigate the evidence in Splunk
* Build saved searches, alerts and a simple dashboard for failed logons
* Practise with Splunk's **Boss of the SOC (BOTS)** datasets
