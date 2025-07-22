rule Quasar_Dropper_072025
{
    meta:
        description = "Detects Quasar Dropper 072025 based on specific string patterns"
        author = "BABAgalae"
        date = "2025-07-22"

    strings:
        $s1 = "A_0" ascii
        $s2 = "A_1" ascii
        $s3 = "A_2" ascii
        $s4 = "A_3" ascii
        $s5 = "421421421421" ascii
        $s6 = "421.421.421.421" ascii
        $s7 = "KKGHIFMPDFBBPDFCKDMPFPFGOIOLPHANCBNG" ascii
        $s8 = "ODNKNCFDHHPJPCMOFFIIHIOEPAPDAKPENFKF" ascii

    condition:
        2 of ($s1, $s2, $s3, $s4) and
        1 of ($s5, $s6, $s7, $s8)
}
