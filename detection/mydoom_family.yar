import "hash"

rule MyDoom_Representative_Sample_SHA256
{
    meta:
        description = "Exact defensive match for a representative MyDoom sample documented in this repository"
        author = "Michel-DV"
        date = "2026-09-06"
        reference = "https://bazaar.abuse.ch/sample/fff0ccf5feaf5d46b295f770ad398b6d572909b00e2b8bcd1b1c286c70cd9151/"
        confidence = "high"

    condition:
        filesize < 5MB and
        hash.sha256(0, filesize) == "fff0ccf5feaf5d46b295f770ad398b6d572909b00e2b8bcd1b1c286c70cd9151"
}

rule MyDoom_Family_Historic_Artifacts
{
    meta:
        description = "Behavioral/static triage rule for historically documented MyDoom-family artifacts"
        author = "Michel-DV"
        date = "2026-09-06"
        reference = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Win32%2FMydoom"
        reference_2 = "https://www.f-secure.com/v-descs/novarg"
        confidence = "medium"
        note = "Family variants differ; validate detections with endpoint and network telemetry"

    strings:
        $dll = "shimgapi.dll" ascii wide nocase
        $exe = "taskmon.exe" ascii wide nocase
        $mutex = /SwebSipcSmtxS[O0]/ ascii wide
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $kazaa = "Software\\Kazaa\\Transfer" ascii wide nocase
        $smtp1 = "MAIL FROM:" ascii nocase
        $smtp2 = "RCPT TO:" ascii nocase
        $smtp3 = "HELO " ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        (
            3 of ($dll, $exe, $mutex, $reg, $kazaa) or
            ($dll and $mutex) or
            ($exe and 2 of ($smtp*))
        )
}
