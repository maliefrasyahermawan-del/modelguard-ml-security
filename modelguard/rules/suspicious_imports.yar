rule SuspiciousImports {
    meta:
        description = "Detects suspicious Python import strings in model files"
        severity    = "HIGH"
        author      = "ModelGuard"
    strings:
        $s1 = "os.system"   ascii
        $s2 = "subprocess"  ascii
        $s3 = "__import__"  ascii
        $s4 = "exec("       ascii
        $s5 = "eval("       ascii
        $s6 = "compile("    ascii
    condition:
        any of them
}
