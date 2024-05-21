from scapy.all import sniff
from scapy.layers.http import HTTP
from scapy.layers.tls.all import TLS
from typing import Optional, Callable


def get_source(packet) -> str:
    return packet[0][1].src

def get_dest(packet) -> str:
    return packet[0][1].dst

def get_highest_layer(packet) -> str:
    if packet.haslayer(TLS):
        return "HTTPS/TLS"
    if packet.haslayer(HTTP):
        return "HTTP"
    return packet.lastlayer()

def get_packet_infos(packet) -> str:
    return f"Protocol : {get_highest_layer(packet)} | {get_source(packet)} -> {get_dest(packet)}"

def sniffer(interface: str, count: Optional[int] = 0, filter: Optional[str] = None, prn: Optional[Callable] = None) -> None:
    for _ in range(count):
        sniff(iface=interface, count=1, filter=filter, prn=prn)

if __name__ == "__main__":
    sniffer(interface="eth0", count=1000, prn=lambda packet: get_packet_infos(packet))