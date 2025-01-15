from scapy.all import rdpcap, ARP, IP
from NetDevice import NetDevice
from consts import *


"""

TODO:
* add also part information
* search better. what if there is mac but no ip?

"""


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_data = rdpcap(pcap_path)
        self.devices: list[NetDevice] = []
        self.ips: list[str] = []
        self.macs: list[str] = []


    def add_dev(self, ip=DEFAULT_IP, mac=DEFAULT_MAC, vendor=DEFAULT_VENDOR):
        if mac == BROADCAST_MAC:
            mac = DEFAULT_MAC
        if ip == BROADCAST_IP:
            ip = DEFAULT_IP


        self.devices.append(NetDevice(ip, mac, vendor))
        if (ip != DEFAULT_IP):
            self.ips.append(ip)
        if (mac != DEFAULT_MAC and mac != BROADCAST_MAC):
            self.macs.append(mac)


    def get_vendor_from_mac(self, mac_addr : str):
        return DEFAULT_VENDOR


    def add_devices_from_pkt(self, pkt):
        if ARP not in pkt:
            return None
        src_mac = pkt.src
        if src_mac not in self.macs:
            src_ip = pkt[ARP].psrc
            src_vendor = self.get_vendor_from_mac(src_mac)
            self.add_dev(src_ip, src_mac, src_vendor)
        dst_mac = pkt.dst
        if dst_mac not in self.macs:
            dst_ip = pkt[ARP].pdst
            dst_vendor = self.get_vendor_from_mac(dst_mac)
            self.add_dev(dst_ip, dst_mac, dst_vendor)


    def add_devices_from_pcap(self):
        for pkt in self.pcap_data:
            self.add_devices_from_pkt(pkt)


    def get_packet_ips(self, pkt):
        if ARP in pkt:
            return pkt[ARP].psrc, pkt[ARP].pdst
        if IP in pkt:
            return pkt[IP].src, pkt[IP].dst
        return ()


    def get_ips(self):
        """
        returns a list of ip addresses (strings) that appear in the pcap
        """
        return self.ips


    def get_macs(self):
        """
        returns a list of MAC addresses (strings) that appear in the pcap
        """
        return self.macs


    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with given IP
        """
        for dev in self.devices:
            if ip == dev.ip:
                d = vars(dev)
                print(d)
                return d
        return {}


    def get_info(self):
        """
        returns a list of dicts with information about every device in the pcap
        """
        info_list = []
        for dev in self.devices:
            info_list.append(vars(dev))
        return info_list


    def __repr__(self):
        return self.devices

    def __str__(self):
        return f"Analyzer with data: \n{self.devices}"
    

if __name__ == "__main__":
    analyzer = AnalyzeNetwork('pcap-00.pcapng')
    analyzer.add_devices_from_pcap()
    print(analyzer.get_info())
    
