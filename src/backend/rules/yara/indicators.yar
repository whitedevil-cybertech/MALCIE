// ==============================================================================
// MALCIE Production YARA Rules
// Author: MALCIE Security Engine
// Purpose: Multi-stage static detection rules for endpoint and email artifacts.
// ==============================================================================

rule Suspicious_PowerShell_EncodedCommand : suspicious execution
{
    meta:
        description = "Detects PowerShell execution with encoded command, execution bypass, or hidden window"
        author = "MALCIE Engine"
        severity = "medium"
        category = "execution"
        mitre_attack = "T1059.001"
        detection_purpose = "Identifies attempts to execute obscured PowerShell scripts common in initial access and execution stages."
    strings:
        $ps = "powershell" nocase
        $enc1 = "-enc" nocase
        $enc2 = "-EncodedCommand" nocase
        $w_hidden = "-WindowStyle Hidden" nocase
        $nop = "-nop" nocase
        $ep_bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        $ps and ($enc1 or $enc2 or $w_hidden or $nop or $ep_bypass)
}

rule Suspicious_Downloader_Artifact : downloader network
{
    meta:
        description = "Detects common suspicious download commands, utility staging, or network API imports"
        author = "MALCIE Engine"
        severity = "high"
        category = "downloader"
        mitre_attack = "T1105"
        detection_purpose = "Identifies binaries or artifacts configured to pull second-stage payloads from remote endpoints."
    strings:
        $url1 = "URLDownloadToFile" ascii wide
        $url2 = "InternetReadFile" ascii wide
        $url3 = "WinHttpOpen" ascii wide
        $cmd1 = "certutil -urlcache" nocase
        $cmd2 = "bitsadmin /transfer" nocase
    condition:
        any of them
}

rule Suspicious_Embedded_PE : dropper
{
    meta:
        description = "Detects multiple embedded DOS stub signatures indicating dropped or nested PE executables"
        author = "MALCIE Engine"
        severity = "high"
        category = "dropper"
        mitre_attack = "T1027.005"
        detection_purpose = "Identifies dropper or multi-stage payloads carrying embedded executable binaries."
    strings:
        $dos_stub = "This program cannot be run in DOS mode" ascii
    condition:
        #dos_stub > 1
}

rule Ransomware_Behavior_Indicators : ransomware impact
{
    meta:
        description = "Detects volume shadow copy deletion, recovery disablement, or backup tampering commands"
        author = "MALCIE Engine"
        severity = "critical"
        category = "impact"
        mitre_attack = "T1490"
        detection_purpose = "Flags destructive system modifications designed to prevent data recovery during ransomware attacks."
    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "vssadmin.exe delete shadows /all /quiet" nocase
        $bcd1 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $bcd2 = "bcdedit /set {default} recoveryenabled no" nocase
        $wmic1 = "wmic shadowcopy delete" nocase
        $wbadmin1 = "wbadmin delete catalog -quiet" nocase
    condition:
        any of them
}

rule Persistence_Registry_Startup : persistence
{
    meta:
        description = "Detects registry keys or commands frequently abused for user-level or system-level persistence"
        author = "MALCIE Engine"
        severity = "high"
        category = "persistence"
        mitre_attack = "T1547.001"
        detection_purpose = "Identifies persistence mechanisms that ensure execution upon user login or system reboot."
    strings:
        $reg_run1 = "CurrentVersion\\Run" nocase ascii wide
        $reg_run2 = "CurrentVersion\\RunOnce" nocase ascii wide
        $schtask = "schtasks /create" nocase
        $startup_dir = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase ascii wide
    condition:
        any of them
}

rule Process_Injection_Capabilities : defense_evasion injection
{
    meta:
        description = "Detects Windows API references commonly combined for process hollowing and remote thread injection"
        author = "MALCIE Engine"
        severity = "high"
        category = "defense_evasion"
        mitre_attack = "T1055"
        detection_purpose = "Identifies code designed to inject malicious shellcode or DLLs into remote legitimate processes."
    strings:
        $api_valloc = "VirtualAllocEx" ascii wide
        $api_wpm = "WriteProcessMemory" ascii wide
        $api_crt = "CreateRemoteThread" ascii wide
        $api_queue_apc = "NtQueueApcThread" ascii wide
        $api_unmap = "ZwUnmapViewOfSection" ascii wide
    condition:
        ($api_valloc and $api_wpm and ($api_crt or $api_queue_apc or $api_unmap))
}

rule Suspicious_Packer_Signatures : packer obfuscation
{
    meta:
        description = "Detects runtime packer section signatures and common compressor markers"
        author = "MALCIE Engine"
        severity = "medium"
        category = "obfuscation"
        mitre_attack = "T1027.002"
        detection_purpose = "Identifies runtime packed executables that conceal underlying payload logic and hashes."
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $aspack = ".aspack" ascii nocase
        $fsg = ".fsg" ascii nocase
        $pecompact = "PECompact2" ascii nocase
    condition:
        ($upx0 and $upx1) or $aspack or $fsg or $pecompact
}

rule Credential_Dumping_Signatures : credential_access
{
    meta:
        description = "Detects API references and strings associated with LSASS memory dumping and credential extraction"
        author = "MALCIE Engine"
        severity = "critical"
        category = "credential_access"
        mitre_attack = "T1003.001"
        detection_purpose = "Identifies tooling aimed at extracting credentials and security tokens from system memory."
    strings:
        $minidump = "MiniDumpWriteDump" ascii wide
        $lsass = "lsass.exe" nocase ascii wide
        $sekurlsa = "sekurlsa" nocase ascii
        $mimikatz = "mimikatz" nocase ascii wide
    condition:
        ($minidump and $lsass) or $sekurlsa or $mimikatz
}
