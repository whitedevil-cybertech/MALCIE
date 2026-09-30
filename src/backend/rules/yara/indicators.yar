rule Suspicious_PowerShell_EncodedCommand : suspicious execution
{
    meta:
        description = "Detects PowerShell execution with encoded command or hidden window"
        author = "MALCIE Engine"
        severity = "medium"
        category = "execution"
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $w_hidden = "-WindowStyle Hidden" nocase
        $nop = "-nop" nocase
    condition:
        $ps and ($enc1 or $enc2 or $w_hidden or $nop)
}

rule Suspicious_Downloader_Artifact : downloader network
{
    meta:
        description = "Detects common suspicious download commands or API references"
        author = "MALCIE Engine"
        severity = "high"
        category = "downloader"
    strings:
        $url1 = "URLDownloadToFile" ascii wide
        $url2 = "InternetReadFile" ascii wide
        $cmd1 = "certutil -urlcache" nocase
        $cmd2 = "bitsadmin /transfer" nocase
    condition:
        any of them
}

rule Suspicious_Embedded_PE : dropper
{
    meta:
        description = "Detects embedded MZ and PE signatures indicating nested executables"
        author = "MALCIE Engine"
        severity = "medium"
        category = "dropper"
    strings:
        $dos_stub = "This program cannot be run in DOS mode" ascii
    condition:
        #dos_stub > 1
}

rule Test_Indicator_Rule : test validation
{
    meta:
        description = "Test rule for MALCIE static analysis pipeline verification"
        author = "MALCIE Test Suite"
        severity = "low"
        category = "test"
    strings:
        $test_string = "MALCIE_TEST_INDICATOR_SAMPLE" ascii wide
    condition:
        $test_string
}
