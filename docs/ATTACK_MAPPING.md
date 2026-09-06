# MITRE ATT&CK mapping - MyDoom

> **Mapping type:** analyst-derived, based on historically documented MyDoom-family behavior. This repository does not claim that MITRE maintains an official MyDoom software entry covering these mappings.

| Behavior | ATT&CK | Rationale | Confidence |
| --- | --- | --- | --- |
| Malicious email attachment | T1566.001 - Spearphishing Attachment | MyDoom primarily propagated as executable/archived email attachments. ATT&CK's parent Phishing technique also explicitly covers non-targeted mass-malspam campaigns. | High |
| User opens malicious attachment | T1204.002 - User Execution: Malicious File | Initial execution depends on the recipient opening the attached malicious file. | High |
| Double extensions / deceptive filenames | T1036.007 - Masquerading: Double File Extension | Historically documented filenames include double-extension patterns intended to hide the executable type. | High |
| UPX packing | T1027.002 - Obfuscated Files or Information: Software Packing | Historical analyses document UPX-packed MyDoom samples. | High |
| File-system search for email addresses | T1083 - File and Directory Discovery | The worm searches files and selected locations for addresses to use during propagation. | Medium |
| Registry Run-key persistence | T1547.001 - Registry Run Keys / Startup Folder | The worm creates Run-key values such as TaskMon to execute at startup/logon. | High |
| Registry modification | T1112 - Modify Registry | Run keys, Kazaa configuration reads/writes in some variants, and COM references are central to host configuration. | High |
| COM object hijacking / DLL load | T1546.015 - Component Object Model Hijacking | Microsoft documents CLSID InProcServer32 values redirected to the MyDoom backdoor DLL. | High |
| Receive and execute an additional executable | T1105 - Ingress Tool Transfer | Historical backdoor behavior includes accepting an additional executable on the infected host. | High |
| Use compromised host as proxy | T1090 - Proxy | The MyDoom.A backdoor can relay TCP traffic through the victim. | High |
| HTTP DDoS flood | T1498.001 - Network Denial of Service: Direct Network Flood | MyDoom.A used many infected systems to send repeated HTTP requests to the target. | High |

## Notes

- ATT&CK is a behavioral taxonomy, not a malware-signature database. Mapping a historical worm to modern technique IDs requires interpretation.
- Family variants differ. A technique should only be associated with a concrete sample when the underlying behavior has been observed or is supported by reliable sample-specific reporting.
- `T1566.001` is named *Spearphishing Attachment*, while MyDoom is famous for non-targeted mass mailing. The broader `T1566 Phishing` technique explicitly recognizes non-targeted malware-spam campaigns; `T1566.001` is used here for the attachment delivery mechanism.

## MITRE references

- https://attack.mitre.org/techniques/T1566/
- https://attack.mitre.org/techniques/T1566/001/
- https://attack.mitre.org/techniques/T1204/002/
- https://attack.mitre.org/techniques/T1036/007/
- https://attack.mitre.org/techniques/T1027/002/
- https://attack.mitre.org/techniques/T1083/
- https://attack.mitre.org/techniques/T1547/001/
- https://attack.mitre.org/techniques/T1112/
- https://attack.mitre.org/techniques/T1546/015/
- https://attack.mitre.org/techniques/T1105/
- https://attack.mitre.org/techniques/T1090/
- https://attack.mitre.org/techniques/T1498/001/
