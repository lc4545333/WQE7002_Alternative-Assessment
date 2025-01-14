from abc import ABCMeta
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP_am, ARP
import threading
import queue
from abc import ABCMeta,abstractmethod

class PacketPart(metaclass=ABCMeta):
    @abstractmethod
    def create_part(self):
        pass

class Ether_Part(PacketPart):
    def __init__(self,mac_address='ff:ff:ff:ff:ff:ff'):
        self.mac_addr = mac_address
    def create_part(self):
        ether_part = Ether(dst= self.mac_addr)
        return ether_part

class IpList(PacketPart):
    def __init__(self,ip_and_mask):
        self.ip_and_mask = ip_and_mask

    def create_part(self):
        ip_list = IP(dst=self.ip_and_mask)
        return ip_list

class ARP_part(PacketPart):
    def __init__(self,ip_dst):
        self.ip_dst = ip_dst
    def create_part(self):
        ARP_part = ARP(pdst= self.ip_dst)
        return ARP_part

show_interfaces()
interfaces = get_if_list()
print(interfaces)