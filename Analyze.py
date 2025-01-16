from scapy.all import rdpcap, ARP, IP, Ether, ICMP
from NetDevice import NetDevice
from consts import *
from pprint import pprint

"""

TODO:

"""


class AnalyzeNetwork:
    def __init__(self):
        self.devices: list[NetDevice] = []

    def find_merge_dev(self, ip=DEFAULT_IP, mac=DEFAULT_MAC):
        found_dev = None
        devs_to_remove = []
        for dev in self.devices:
            if (ip == dev.ip and ip not in NOT_DEV_IPS) or \
                    (mac == dev.mac and mac not in NOT_DEV_MACS):

                if found_dev:
                    self.merge_devs(found_dev, dev)
                    devs_to_remove.append(dev)
                else:
                    found_dev = dev

        if devs_to_remove:
            for dev in devs_to_remove:
                self.devices.remove(dev)

        return found_dev


    def merge_devs(self, dev: NetDevice, merging_dev: NetDevice):
        """
        merge merging_dev into dev
        """
        if dev.ip == DEFAULT_IP and merging_dev.ip not in NOT_DEV_IPS:
            dev.set_ip(merging_dev.ip)
        if dev.mac == DEFAULT_MAC and merging_dev.mac not in NOT_DEV_MACS:
            dev.set_mac(merging_dev.mac)


    def add_dev(self, ip=DEFAULT_IP, mac=DEFAULT_MAC):
        if ip in NOT_DEV_IPS:
            ip = DEFAULT_IP
        if mac in NOT_DEV_MACS:
            mac = DEFAULT_MAC

        dev = self.find_merge_dev(ip, mac)
        if not dev:  
            if (ip not in NOT_DEV_IPS or mac not in NOT_DEV_MACS):
                self.devices.append(NetDevice(ip, mac, calc_vendor=True))
            return
        
        self.merge_devs(dev, NetDevice(ip, mac))


    def add_devices_from_pkt(self, pkt):
        if Ether not in pkt:
            return
        src_mac = pkt.src
        dst_mac = pkt.dst
        self.add_dev(mac=src_mac)
        self.add_dev(mac=dst_mac)
        if ARP in pkt:
            self.add_dev(pkt[ARP].psrc, pkt[ARP].hwsrc)
            self.add_dev(pkt[ARP].pdst, pkt[ARP].hwdst)
        if IP in pkt: 
            self.add_dev(ip=pkt[IP].src)
            self.add_dev(ip=pkt[IP].dst)


    def add_icmp_fields_from_pkt(self, pkt):
        if ICMP not in pkt:
            return
        mac = pkt.src
        dev = self.get_dev_by_mac(mac)
        if not dev:
            return
        ttl = pkt[IP].ttl
        dev.icmp_fields["ttls"].append(ttl)
        dev.icmp_fields["payload_lens"].append(len(pkt.load))
        if pkt[IP].flags & ICMP_DF_SET:
            dev.icmp_fields["DFs"].append(True)
        else:
            dev.icmp_fields["DFs"].append(False)


    def add_devices_from_pcap(self, pcap_path: str):
        pcap_data = rdpcap(pcap_path)
        for pkt in pcap_data:
            self.add_devices_from_pkt(pkt)
        for pkt in pcap_data:
            self.add_icmp_fields_from_pkt(pkt)
        for dev in self.devices:
            dev.guess_os()


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
        return [dev.ip for dev in self.devices if dev.ip not in NOT_DEV_IPS] 

    def get_macs(self):
        """
        returns a list of MAC addresses (strings) that appear in the pcap
        """
        return [dev.mac for dev in self.devices if dev.mac not in NOT_DEV_MACS] 

    def get_dev_by_ip(self, ip: str) -> NetDevice:
        for dev in self.devices:
            if ip == dev.ip:
                return dev
        return None
    
    def get_dev_by_mac(self, mac: str) -> NetDevice:
        for dev in self.devices:
            if mac == dev.mac:
                return dev
        return None

    def get_info_by_ip(self, ip: str) -> list[str]:
        """
        returns a dict with all information about the device with given IP
        """
        dev = self.get_dev_by_ip(ip)
        if dev:
            return vars(dev)
        return {}
    
    def get_info_by_mac(self, mac: str) -> list[str]:
        """
        returns a dict with all information about the device with given MAC
        """
        dev = self.get_dev_by_mac(mac)
        if dev:
            return vars(dev)
        return {}

    def get_info(self) -> list[NetDevice]:
        """
        returns a list of dicts with information about every device in the pcap
        """
        info_list = []
        for dev in self.devices:
            info_list.append(vars(dev))
        return info_list
    

    def guess_os(self, dev_info: dict[str, str]) -> list[str]:
        ...


    def __repr__(self):
        return self.devices

    def __str__(self):
        return f"Analyzer with data: \n{self.devices}"
    

if __name__ == "__main__":
    analyzer = AnalyzeNetwork()
    analyzer.add_devices_from_pcap('pcap-02.pcapng')
    info = analyzer.get_info()
    pprint(info)
    print()
    pprint(analyzer.get_ips())
    pprint(analyzer.get_macs())
    
