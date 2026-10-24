rule DetectBase64Payload {
    meta:
        description = "Detects base64-encoded payload indicators in model files"
        severity    = "MEDIUM"
        author      = "ModelGuard"
    strings:
        $b64_decode1 = "base64.b64decode"    ascii
        $b64_decode2 = "b64decode("          ascii
        $b64_decode3 = "from_base64"         ascii
        $b64_decode4 = ".decode('base64')"   ascii
        $codecs_b64  = "codecs.decode"       ascii
        $b64_exec    = "exec(base64"         ascii nocase
    condition:
        any of them
}

rule DetectEncodedPowerShell {
    meta:
        description = "Detects encoded/obfuscated PowerShell commands in model files"
        severity    = "HIGH"
        author      = "ModelGuard"
    strings:
        $ps1 = "powershell -enc"               ascii nocase
        $ps2 = "powershell -e "                ascii nocase
        $ps3 = "powershell.exe -enc"           ascii nocase
        $ps4 = "powershell -EncodedCommand"    ascii nocase
        $ps5 = "powershell -ExecutionPolicy Bypass" ascii nocase
        $ps6 = "powershell -W Hidden"          ascii nocase
        $ps7 = "IEX("                          ascii
        $ps8 = "Invoke-Expression"             ascii
    condition:
        any of them
}
