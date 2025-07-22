rule Quasar_Dropper_072025 {
    meta:
        description = "Detects Quasar Dropper 072025 based on specific strings"
        author = "BABAgalae"
        date = "2025-07-22"
        threat_name = "Quasar.Dropper.072025"

    strings:
        $a0 = "A_0" ascii
        $a1 = "A_1" ascii
        $a2 = "A_2" ascii
        $a3 = "A_3" ascii
        $s1 = "Version=421421421421" ascii
        $s2 = "KKGHIFMPDFBBPDFCKDMPFPFGOIOLPHANCBNG" ascii
        $s3 = "ODNKNCFDHHPJPCMOFFIIHIOEPAPDAKPENFKF" ascii

    condition:
        (2 of ($a*)) and (1 of ($s*))
}
