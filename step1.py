from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP_am, ARP
import threading
import queue
from abc import ABCMeta,abstractmethod

class ScanPacketPart(metaclass=ABCMeta):
    @abstractmethod
    def create_part(self):
        pass

class IpList(ScanPacketPart):
    def __init__(self,ip_and_mask):
        self.ip_and_mask = ip_and_mask

    def create_part(self):
        ip_list = IP(dst=self.ip_and_mask)
        return ip_list

class Ether_Part(ScanPacketPart):
    def __init__(self,mac_address='ff:ff:ff:ff:ff:ff'):
        self.mac_addr = mac_address
    def create_part(self):
        ether_part = Ether(dst= self.mac_addr)
        return ether_part

class ARP_part(ScanPacketPart):
    def __init__(self,ip_dst):
        self.ip_dst = ip_dst
    def create_part(self):
        ARP_part = ARP(pdst= self.ip_dst)
        return ARP_part

class ICMP_Part(ScanPacketPart):
    def __init__(self,code,type):
        self.type = type
        self.code = code
    def create_part(self):
        icmp_part = ICMP(type = self.type,code = self.code)
        return icmp_part

class TCP_Part(ScanPacketPart):
    def __init__(self, port, flags):
        self.port = port
        self.flags = flags

    def create_part(self):
        tcp_part = TCP(dport=self.port,flags=self.flags)
        return tcp_part

class UDP_Part(ScanPacketPart):
    def __init__(self,dport):
        self.dport = dport
    def create_part(self):
        udp_part = UDP(dport = self.dport)
        return udp_part

class ScanPacket(metaclass=ABCMeta):
    @abstractmethod
    def create_packet(self):
        pass

class ARP_packet(ScanPacket):
    def __init__(self,ip_addr_and_mask):
        self.dst_ip_list = ip_addr_and_mask
    def create_packet(self):
        ip_part = IpList(self.dst_ip_list).create_part()
        packet_list = []
        eth_part = Ether_Part().create_part()
        #hexdump(eth_part)
        for dst_ip in ip_part:
            arp_part = ARP_part(str(dst_ip.dst)).create_part()
            arp_packet = eth_part/arp_part
            packet_list.append(arp_packet)
        #hexdump(packet_list[2])
        return packet_list

class ICMP_packet(ScanPacket):
    def __init__(self,ip_addr_and_mask,icmp_type=8,icmp_code=0):
        self.ip_addr_and_mask = ip_addr_and_mask
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
    def create_packet(self):
        icmp_part = ICMP_Part(self.icmp_type,self.icmp_code).create_part()
        ip_part = IpList(self.ip_addr_and_mask).create_part()
        ICMP_packet_list = ip_part/icmp_part
        return ICMP_packet_list

class UDP_packet(ScanPacket):
    def __init__(self,ip_addr_and_mask,dport = 41025):
        self.dport = dport
        self.ip_addr_and_mask = ip_addr_and_mask
    def create_packet(self):
        udp_part = UDP_Part(self.dport).create_part()
        ip_part = IpList(self.ip_addr_and_mask).create_part()
        UDP_packet_list = ip_part/udp_part
        return UDP_packet_list

class TCP_packet(ScanPacket):
    def __init__(self,ip_addr_and_mask,dport=443,flags='S'):
        self.ip_addr_and_mask = ip_addr_and_mask
        self.dport = dport
        self.flags = flags
    def create_packet(self):
        tcp_part = TCP_Part(self.dport,self.flags).create_part()
        ip_part = IpList(self.ip_addr_and_mask).create_part()
        TCP_packet_list = ip_part/tcp_part
        return TCP_packet_list

class TCP_packet(ScanPacket):
    def __init__(self,ip_addr_and_mask,dport=443,flags='UPF'):
        self.ip_addr_and_mask = ip_addr_and_mask
        self.dport = dport
        self.flags = flags
    def create_packet(self):
        tcp_part = TCP_Part(self.dport,self.flags).create_part()
        ip_part = IpList(self.ip_addr_and_mask).create_part()
        TCP_packet_list = ip_part/tcp_part
        return TCP_packet_list

class PacketFactoryBase(metaclass=ABCMeta):
    @staticmethod
    @abstractmethod
    def create_scan_packet(self,scan_type):
        pass

class PacketFactory(PacketFactoryBase):
    @staticmethod
    def create_scan_packet(scan_type: str, **kwargs) -> ScanPacket:
        scan_map = {
            'arp': ARP_packet,
            'icmp' :ICMP_packet,
            'tcp':TCP_packet,
            'udp':UDP_packet
        }
        if scan_type not in scan_map:
            raise ValueError(f"Unsupported scan type: {scan_type}")

        return scan_map[scan_type](**kwargs)



class ScanResult:
    def __init__(self):
        self.active_hosts = set()
        self.lock = threading.Lock()

    def add_host(self, ip):
        with self.lock:
            self.active_hosts.add(ip)


class NetworkScanner:
    def __init__(self,timeout = 1):
        self.timeout = timeout
        self.result = ScanResult()
        self.packet_queue = queue.Queue()


    def _send_packet(self, packet, retry=0):
        try:
            if Ether in packet:
                response = srp1(packet, timeout=self.timeout, verbose=False, retry=retry,iface='VMware Virtual Ethernet Adapter for VMnet8')
            else:
                response = sr1(packet, timeout=self.timeout, verbose=False, retry=retry,iface='VMware Virtual Ethernet Adapter for VMnet8')
            if response:
                # 从响应包中提取源IP地址
                if IP in response:
                    self.result.add_host(response[IP].src)
                elif ARP in response:
                    self.result.add_host(response[ARP].psrc)
        except Exception as e:
            print(f"Error sending packet: {e}")

    def _scan_worker(self):
        while True:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._send_packet(packet)
                self.packet_queue.task_done()
                print(packet)
            except queue.Empty:
                break
            except Exception as e:
                print(f"Worker error: {e}")
                continue

    def scan(self, target_range, scan_type='tcp', thread_count=100, **kwargs):
        """
        执行网络扫描
        参数:
            target_range: 目标IP范围 (例如 "192.168.1.0/24")
            scan_type: 扫描类型 ('tcp', 'udp', 'icmp', 'arp')
            thread_count: 扫描线程数
            **kwargs: 传递给具体扫描包构造函数的参数
        """
        try:
            scan_packet = PacketFactory.create_scan_packet(
                scan_type,
                ip_addr_and_mask = target_range,
                **kwargs
            )
            packet_list = scan_packet.create_packet()
            if not isinstance(packet_list, list):
                packet_list = [packet_list]


            for packet in packet_list:
                self.packet_queue.put(packet)
                print(packet)

            print(1)

            # 创建并启动工作线程
            threads = []
            for _ in range(min(thread_count, self.packet_queue.qsize())):
                t = threading.Thread(target=self._scan_worker)
                t.daemon = True
                t.start()
                threads.append(t)

            self.packet_queue.join()
            for t in threads:
                t.join()

            return self.result.active_hosts

        except IOError as e:
            print(f"Scan error: {e}")
            return set() #返回空集合

