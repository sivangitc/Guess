DEFAULT_IP = "unknown"
DEFAULT_MAC = "unknown"
DEFAULT_VENDOR = "unknown"

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_IP = "255.255.255.255"

NOT_DEV_IPS = [DEFAULT_IP, BROADCAST_IP]
NOT_DEV_MACS = [DEFAULT_MAC, BROADCAST_MAC, "00:00:00:00:00:00"]

OS_ICMP_TTL = {
    32: ["Windows"] ,
    60: ["Stratus"],
    64: ["Linux", "MacOS"], 
    128: ["Windows"], 
    254: ["Solaris", "AIX"],
    255: ["Linux", "Stratus"]
}

