rule DetectShellcode {
    meta:
        description = "Detects potential shellcode and exploit payload patterns"
        severity    = "CRITICAL"
        author      = "ModelGuard"
    strings:
        $nop_sled         = { 90 90 90 90 90 90 90 90 90 90 }
        $int3_chain       = { CC CC CC CC CC }
        $linux_execve     = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E }
        $msf_marker       = "PAYLOAD:" ascii
        $shellcode_tag    = "shellcode" ascii nocase
        $meterpreter      = "meterpreter" ascii nocase
        $cobalt_marker    = { FC 48 83 E4 F0 }
        $egg_hunter       = { 66 81 CA FF 0F 42 52 6A 02 }
    condition:
        $nop_sled or $int3_chain or $linux_execve or $msf_marker or
        $meterpreter or $cobalt_marker or $egg_hunter or
        (filesize < 10MB and $shellcode_tag and (#shellcode_tag > 2))
}
