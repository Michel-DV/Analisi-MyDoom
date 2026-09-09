# Changelog

## 2.0.1 - 2026-09-09

### Changed

- made `MyDoom_Malware_Analysis_and_Detection_Report_v2.pdf` the single authoritative report in the repository
- simplified the README and repository tree around the maintained v2 analysis package

### Removed

- removed the superseded original Italian PDF from the current tree to avoid duplicate editions, conflicting quality levels, and reader confusion

## 2.0.0 - 2026-09-06

### Added

- rebuilt `MyDoom_Malware_Analysis_and_Detection_Report_v2.pdf`
- reproducible PDF source in `report/report_data.json` and `report/build_report.py`
- selected original evidence images preserved in the new report
- evidence scope and confidence model
- analyst-derived MITRE ATT&CK mapping
- machine-readable IOC exports in JSON and CSV
- YARA detection rules
- Sigma rules for registry persistence, COM persistence, file artifacts and SMTP behavior
- detection engineering and incident-response guidance
- automated GitHub Actions validation for report source, Sigma YAML, YARA compilation and PDF QA

### Changed

- updated document handling from legacy `TLP:WHITE` to `TLP:CLEAR` under FIRST TLP 2.0
- separated representative-sample, family-wide and variant-specific observations
- reframed historical backdoor ports and filenames as triage pivots rather than standalone infection verdicts
- corrected the 1.1% prevalence statistic to its actual Unit 42 telemetry period (2015-2019), rather than presenting it as a 2025/2026 figure
- reframed widely repeated financial-impact numbers as historical estimates with methodology caveats
- rebuilt the README around malware analysis and detection engineering

### Preserved

- historically relevant reverse-engineering figures and screenshots where they add evidentiary value, consolidated into the maintained v2 report
