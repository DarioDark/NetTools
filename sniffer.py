from scapy.all import sniff
from scapy.layers.http import HTTP
from scapy.layers.tls.all import TLS
from typing import Optional, Callable


def get_source(packet) -> str:
    """Get the source IP address of the packet"""
    return packet[0][1].src

def get_dest(packet) -> str:
    """Get the destination IP address of the packet"""
    return packet[0][1].dst

def get_highest_layer(packet) -> str:
    """Get the highest layer of the packet"""
    if packet.haslayer(TLS):
        return "HTTPS/TLS"
    if packet.haslayer(HTTP):
        return "HTTP"
    return packet.lastlayer()

def get_packet_infos(packet) -> str:
    """Get the source, destination and protocol of the packet"""
    return f"Protocol : {get_highest_layer(packet)} | {get_source(packet)} -> {get_dest(packet)}"

def sniffer(interface: str, count: Optional[int] = 0, filter: Optional[str] = None, prn: Optional[Callable] = None) -> None:
    """Sniff packets on the given interface with the given filter and print the packet informations using the given function"""
    for _ in range(count):
        try:
            sniff(iface=interface, count=1, filter=filter, prn=prn)
        except KeyboardInterrupt:
            break
    print("[*]Sniffing finished")

if __name__ == "__main__":
    sniffer(interface="eth0", count=1000, prn=lambda packet: get_packet_infos(packet))