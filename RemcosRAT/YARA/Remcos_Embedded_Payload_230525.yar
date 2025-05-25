rule Remcos_Embedded_Payload
{
    meta:
        author = "BABAgala"
        description = "Detects %x% followed by newline and the start of a Base64 encoded PE file, indicating an embedded payload (KSbho.png)."
        date = "2025-05-25"
        severity = "high"
        reference = "https://www.linkedin.com/posts/gal-akavia-7b1288201_cybersecurity-malware-threatintel-activity-7332464307345031168-OWfI?utm_source=share&utm_medium=member_desktop&rcm=ACoAADN56nUBFPfdnwY4uMMIUJ8wjqQR7PKFveI"

    strings:
        $payload_start = { 25 78 25 0D 0A 54 56 71 51 41 41 4D 41 41 41 41 45 41 41 41 41 2F 2F 38 41 41 }

    condition:
        $payload_start
}
