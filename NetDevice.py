from consts import *
from requests import get
from time import sleep
from configparser import ConfigParser

config = ConfigParser()
config.read('settings.ini')

class NetDevice:
    def __init__(self, ip=DEFAULT_IP, mac=DEFAULT_MAC, calc_vendor: bool=False):
        self.ip = ip
        self.mac = mac
        self.vendor = DEFAULT_VENDOR
        if calc_vendor:
            self.vendor = self.get_vendor_from_mac()
        self.ttls = []
        self.os = []

    def set_ip(self, ip: str):
        self.ip = ip

    def set_mac(self, mac: str):
        self.mac = mac
        self.vendor = self.get_vendor_from_mac()

    def get_vendor_from_mac(self):
        query_api = config.getboolean('Vendor', 'query_api')
        if not query_api: # dont annoy the api people
            return DEFAULT_MAC
        
        mac_for_api = ''.join(self.mac.split(':')[:3])
        macsend = config["Vendor"]["api_url"] + mac_for_api
        sleep(1) # API TOLD ME IM TOO MUCH
        vendorsearch = get(macsend).text
        if "Not Found" in vendorsearch:
            return DEFAULT_MAC
        else:
            return vendorsearch
        
    def guess_os(self):
        if not self.ttls:
            return
        ttl_avg = sum(self.ttls) / len(self.ttls)
        # probably made no more than 10 hops
        possible_oss = [oss for (t, oss) in OS_ICMP_TTL.items() if t >= ttl_avg and t - ttl_avg <= 10]
        self.os = [os for oss in possible_oss for os in oss]
        return self.os

    def __str__(self):
        return f"<{self.mac}> <{self.ip}> <{self.vendor}>"
    
    def __repr__(self):
        return self.__str__()
    