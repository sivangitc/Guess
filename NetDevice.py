from consts import *
from requests import get
from time import sleep

class NetDevice:
    def __init__(self, ip=DEFAULT_IP, mac=DEFAULT_MAC, calc_vendor: bool=False):
        self.ip = ip
        self.mac = mac
        self.vendor = DEFAULT_VENDOR
        if calc_vendor:
            self.vendor = self.get_vendor_from_mac()

    def set_ip(self, ip: str):
        self.ip = ip

    def set_mac(self, mac: str):
        self.mac = mac
        self.vendor = self.get_vendor_from_mac()

    def get_vendor_from_mac(self):
        mac_for_api = ''.join(self.mac.split(':')[:3])
        macsend = MAC_VENDOR_API_URL + mac_for_api
        sleep(1) # API TOLD ME IM TOO MUCH
        vendorsearch = get(macsend).text
        if "Not Found" in vendorsearch:
            return DEFAULT_MAC
        else:
            return vendorsearch

    def __str__(self):
        return f"<{self.mac}> <{self.ip}> <{self.vendor}>"
    
    def __repr__(self):
        return self.__str__()
    