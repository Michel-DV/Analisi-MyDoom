# Security and research scope

This repository is a defensive malware-analysis and detection-engineering project.

## Included

- historical MyDoom behavior analysis
- defensive IOCs and confidence/scope metadata
- YARA and Sigma detections
- MITRE ATT&CK mapping
- incident-response and hunting guidance
- reproducible report-generation tooling

## Intentionally not included

- live malware samples
- weaponized MyDoom source code
- exploit or persistence tooling
- operational backdoor-control clients
- instructions for interacting with compromised third-party systems

Historical offensive behavior is documented only to support analysis, detection and incident response.

## IOC handling

A hash can identify a specific sample, but most filenames, registry values and network ports are not globally unique. Treat those indicators as investigation pivots and correlate them with process ownership, file hashes, persistence events and network behavior before declaring compromise.

## Reporting issues

For errors in the report, IOC scope, ATT&CK mapping or detection rules, open a GitHub issue with the affected file/section and supporting evidence. Do not attach live malware binaries to public issues.
