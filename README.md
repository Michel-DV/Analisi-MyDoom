# MyDoom - Malware Analysis & Detection Engineering

[![Build report](https://github.com/Michel-DV/Analisi-MyDoom/actions/workflows/build-report.yml/badge.svg)](https://github.com/Michel-DV/Analisi-MyDoom/actions/workflows/build-report.yml)

> **Status:** v2.0  
> **Handling:** TLP:CLEAR  
> **Focus:** historical malware analysis, defensive research, IOC engineering, YARA/Sigma detection and incident-response guidance

MyDoom is one of the defining mass-mailing worm families of the early 2000s. This repository turns the historical analysis into a reproducible **malware-analysis and detection-engineering package** rather than leaving the project as a standalone PDF.

## Current report

### [MyDoom Malware Analysis & Detection Report v2](./MyDoom_Malware_Analysis_and_Detection_Report_v2.pdf)

The v2 report is the recommended edition. It preserves selected evidence figures from the original analysis while rebuilding the document around:

- evidence scope and confidence
- infection and propagation lifecycle
- persistence and backdoor behavior
- network hunting opportunities
- variant-aware analysis
- analyst-derived MITRE ATT&CK mapping
- machine-readable IOCs
- YARA and Sigma detections
- incident-response playbook
- limitations and data-quality notes

The original Italian report is retained as a legacy/source edition: [Analisi Tecnica del Malware MyDoom.pdf](./Analisi%20Tecnica%20del%20Malware%20MyDoom.pdf).

## Why v2 exists

Historical malware reports often mix family-wide behavior, individual sample artifacts and variant-specific observations. That can create over-broad detections or inaccurate conclusions.

This edition explicitly separates:

| Evidence type | Meaning |
| --- | --- |
| **Representative sample** | Hashes and observations tied to one documented executable |
| **Family-wide** | Behavior repeatedly described across MyDoom variants |
| **Variant-specific** | Ports, targets or persistence artifacts that apply only to selected variants |
| **Analyst-derived** | Modern ATT&CK mappings and defensive correlations built from documented behavior |

A filename or open port is therefore treated as a **triage signal**, not automatic proof of infection.

## Repository structure

```text
Analisi-MyDoom/
├── MyDoom_Malware_Analysis_and_Detection_Report_v2.pdf
├── Analisi Tecnica del Malware MyDoom.pdf      # legacy/original edition
├── detection/
│   ├── mydoom_family.yar
│   └── sigma/
│       ├── mydoom_registry_run_persistence.yml
│       ├── mydoom_com_hijack_shimgapi.yml
│       ├── mydoom_file_artifacts.yml
│       └── mydoom_smtp_from_legacy_process.yml
├── iocs/
│   ├── iocs.json
│   └── iocs.csv
├── docs/
│   ├── ATTACK_MAPPING.md
│   └── DETECTION.md
├── report/
│   ├── build_report.py
│   ├── report_data.json
│   └── qa.json
└── .github/workflows/build-report.yml
```

## Defensive detection pack

### YARA

[`detection/mydoom_family.yar`](./detection/mydoom_family.yar) contains:

- a high-confidence exact match for the representative SHA-256 documented in this repository
- a medium-confidence family triage rule requiring multiple historical artifacts rather than one generic string

### Sigma

The Sigma pack covers:

- Windows Run-key persistence (`TaskMon` / `Traybar`)
- MyDoom-associated COM `InProcServer32` persistence pointing to `shimgapi.dll`
- high-value legacy file artifacts in Windows system directories
- suspicious outbound SMTP behavior from historically relevant process names

Rules are intentionally marked **experimental** because event fields and normalization differ between Sysmon, EDR platforms and SIEM pipelines.

## IOC pack

Machine-readable data is available in:

- [`iocs/iocs.json`](./iocs/iocs.json)
- [`iocs/iocs.csv`](./iocs/iocs.csv)

The IOC dataset includes confidence, scope and source context. Representative sample identifiers include:

```text
SHA-256  fff0ccf5feaf5d46b295f770ad398b6d572909b00e2b8bcd1b1c286c70cd9151
SHA-1    f91a4d7ac276b8e8b7ae41c22587c89a39ddcea5
MD5       53df39092394741514bc050f3d6a06a9
```

Additional historical pivots include `taskmon.exe`, `shimgapi.dll`, Run-key artifacts, MyDoom-associated CLSID persistence and variant-specific network ports.

## ATT&CK mapping

See [`docs/ATTACK_MAPPING.md`](./docs/ATTACK_MAPPING.md).

The mapping is explicitly **analyst-derived**, because the report is translating historical behavior into the current Enterprise ATT&CK taxonomy. Examples include:

- T1566.001 - malicious email attachment delivery
- T1204.002 - malicious file execution
- T1036.007 - double file extension
- T1027.002 - software packing
- T1547.001 - Registry Run Keys / Startup Folder
- T1546.015 - Component Object Model Hijacking
- T1112 - Modify Registry
- T1105 - Ingress Tool Transfer
- T1090 - Proxy
- T1498.001 - Direct Network Flood

## Detection philosophy

The project prioritizes behavioral correlation over one-off IOCs. A stronger MyDoom-like sequence is:

```text
malicious attachment
        ↓
user execution
        ↓
new PE/DLL in a Windows system directory
        ↓
Run-key or COM persistence
        ↓
unusual SMTP fan-out / legacy backdoor traffic
```

See [`docs/DETECTION.md`](./docs/DETECTION.md) for hunting and incident-response notes.

## Important data-quality correction

The often-quoted **1.1%** MyDoom prevalence figure comes from Palo Alto Networks Unit 42 telemetry covering **2015-2018 and January-June 2019**. It is not presented here as a 2025/2026 global prevalence statistic.

Likewise, historical multi-billion-dollar damage estimates are treated as historical estimates rather than precise audited losses.

## Reproducible report build

The current PDF is generated from [`report/report_data.json`](./report/report_data.json) and [`report/build_report.py`](./report/build_report.py).

GitHub Actions validates:

```text
Python syntax
JSON structure
Sigma YAML parsing
YARA compilation
PDF generation
PDF QA / page checks
```

This keeps the report, rules and IOC package reviewable and reproducible instead of treating the PDF as an opaque binary artifact.

## Safety and scope

This repository is for **malware analysis, threat research, detection engineering and incident-response education**.

It does not distribute a live MyDoom executable, exploit tooling, operational backdoor-control code or instructions for compromising third-party systems. Historical offensive capabilities are described only to the extent necessary to understand and detect the malware.

## License

MIT - see [LICENSE](./LICENSE).
