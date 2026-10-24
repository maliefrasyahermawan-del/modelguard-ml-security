rule DetectC2Domain {
    meta:
        description = "Detects known C2 infrastructure domain patterns in model files"
        severity    = "HIGH"
        author      = "ModelGuard"
    strings:
        $onion      = ".onion"          ascii
        $ngrok      = "ngrok.io"        ascii
        $serveo     = "serveo.net"      ascii
        $dyndns     = "dyndns.org"      ascii
        $noip       = "no-ip.org"       ascii
        $ddns       = "ddns.net"        ascii
        $pastebin   = "pastebin.com"    ascii
        $bit_ly     = "bit.ly/"         ascii
        $tinyurl    = "tinyurl.com"     ascii
        $freeddns   = "freedynamicdns"  ascii nocase
        $portmap    = "portmap.io"      ascii
        $localtonet = "localto.net"     ascii
    condition:
        any of them
}
