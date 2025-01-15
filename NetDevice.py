from consts import *

class NetDevice:
    def __init__(self, ip=DEFAULT_IP, mac=DEFAULT_MAC, vendor=DEFAULT_VENDOR):
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
    
    def __str__(self):
        return f"<{self.mac}> <{self.ip}> <{self.vendor}>"
    