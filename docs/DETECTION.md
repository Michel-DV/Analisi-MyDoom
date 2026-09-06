# Detection engineering notes

Void-free historical malware analysis is most useful when artifacts are translated into observable behavior. This document turns the MyDoom research in this repository into practical defensive hunting guidance.

## Detection model

Use a confidence ladder instead of treating one artifact as proof of infection:

1. **Weak signal** - one legacy filename or one open/listening port.
2. **Moderate signal** - suspicious filename plus Run-key persistence, unusual direct SMTP, or matching COM modification.
3. **Strong signal** - representative hash match, multiple family artifacts on one host, or matching YARA plus behavioral telemetry.
4. **Confirmed incident** - validated malicious sample and/or multiple independent host/network indicators after investigation.

## High-value host telemetry

### Registry

Prioritize writes to:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\TaskMon`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\TaskMon`
- historically documented variant values such as `Traybar`
- MyDoom-associated CLSID `InProcServer32` values pointing to `shimgapi.dll`

Useful telemetry includes Sysmon registry events and EDR registry-change events. Correlate the writer process, signer, path and surrounding file creation.

### Files

Investigate creation of:

- `%SystemRoot%\System32\taskmon.exe`
- `%SystemRoot%\System32\shimgapi.dll`

Do not alert solely on a basename outside the historically relevant path. Common-looking names such as `java.exe`, `services.exe` and `lsass.exe` have high false-positive risk unless path, signature and parent process are abnormal.

### Process and persistence correlation

A useful correlation chain is:

`new PE file in Windows system directory -> Run/COM registry modification -> process execution -> SMTP/network activity`

This is more robust than an isolated IOC.

## Network hunting

### Mass-mailing behavior

The most useful family-wide behavior is high-fan-out outbound SMTP from a workstation or other endpoint that is not an authorized mail relay:

- many destination mail servers
- TCP/25 initiated directly by a user endpoint
- repeated SMTP sessions over a short period
- concurrent DNS MX lookups

This can remain useful even when the malware file hash changes.

### Backdoor ports

Historical MyDoom.A analysis documents the backdoor selecting the first available TCP port from **3127 through 3198**. Later variants used other ports, including **1042**.

Treat these as triage pivots, not standalone infection verdicts. A listening service on one of these ports should be correlated with process ownership, file hash, registry persistence and network activity.

## Included rules

- `detection/mydoom_family.yar` - exact representative sample hash plus a medium-confidence family-artifact rule.
- `detection/sigma/mydoom_registry_run_persistence.yml` - Run-key persistence.
- `detection/sigma/mydoom_com_hijack_shimgapi.yml` - COM persistence referencing `shimgapi.dll`.
- `detection/sigma/mydoom_file_artifacts.yml` - high-value file creation artifacts.
- `detection/sigma/mydoom_smtp_from_legacy_process.yml` - behavior-oriented SMTP triage.

The Sigma rules are intentionally marked **experimental**. Field names and event availability differ between Sysmon, Windows Event Forwarding, EDR products and SIEM normalization pipelines.

## Incident-response pivot sequence

When a MyDoom-like alert fires:

1. Isolate the endpoint if multiple independent indicators agree.
2. Acquire the suspicious file and calculate SHA-256/SHA-1/MD5 without executing it.
3. Check Run keys and documented CLSID paths.
4. Identify the process owning suspicious network connections or listening sockets.
5. Review outbound SMTP fan-out, DNS MX lookups and inbound connections around the alert window.
6. Inspect the Windows hosts file for variant-specific security-site blocking.
7. Hunt across the environment for matching hashes, file paths, registry values and SMTP behavior.
8. Reimage or remediate according to organizational IR policy; do not rely on deleting one file when persistence or a secondary payload may exist.

## Data-quality warning

The MyDoom name covers many variants and decades of samples. IOC packs found online often mix variant-specific artifacts. This repository labels indicators with scope and confidence so defenders can avoid turning historical research into overly broad detections.
