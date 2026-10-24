rule DetectReverseShell {
    meta:
        description = "Detects reverse shell patterns in model files"
        severity    = "CRITICAL"
        author      = "ModelGuard"
    strings:
        $socket      = "socket"         ascii
        $connect     = "connect"        ascii
        $send        = "send"           ascii
        $recv        = "recv"           ascii
        $bash_i      = "/bin/bash -i"   ascii
        $bash_c      = "/bin/bash -c"   ascii
        $sh          = "/bin/sh"        ascii
        $nc_e        = "nc -e"          ascii
        $pty_spawn   = "pty.spawn"      ascii
        $bind_shell  = "bind_shell"     ascii nocase
        $rev_shell   = "reverse_shell"  ascii nocase
    condition:
        ($socket and $connect and ($send or $recv)) or
        ($bash_i or $bash_c or $sh or $nc_e or $pty_spawn) or
        ($bind_shell or $rev_shell)
}
