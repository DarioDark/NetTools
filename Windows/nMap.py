import sys

from multiprocessing import Pool
from scapy.all import (Ether, ARP, srp)

def get_subnet(ip: str) -> str:
    """Get the subnet of the target IP address"""
    splitted_ip = ip.split(".")
    return f"{splitted_ip[0]}.{splitted_ip[1]}.{splitted_ip[2]}"

def get_mac(ip: str, printing: bool = False) -> str | None:
    """Get the MAC address of the target IP address using ARP request"""
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=ip)
    print("[*]Sending ARP request to", ip) if printing else None
    answered, _ = srp(packet, timeout=2, retry= 0, verbose=False)
    for _, r in answered:
        print(f"[+]A device responded : {r[ARP].psrc}, {r[Ether].src}") # prsc is the IP address of the target that responded to the ARP request
        return r[ARP].psrc, r[Ether].src
    print(f"[-]No device responded") if printing else None

def nMap(ip: str) -> list[str] | None:
    """Scan the subnet for all devices"""
    print("[*]Scanning the subnet for all devices...")
    subnet_ips = [f"{get_subnet(ip)}.{i}" for i in range(1, 255)]
    chunk_size = 60  # Smaller chunk size to avoid exceeding the handle limit
    results = []

    with Pool(processes=chunk_size) as pool:
        for i in range(0, len(subnet_ips), chunk_size):
            chunk = subnet_ips[i:i + chunk_size]
            result = pool.map(get_mac, chunk)
            results.extend(result)
            
    pool.join()
    print("[*]Scan completed")
    if len(result) == 0:
        print("[-]No devices found")
        return
    return [addr for addr in result if addr is not None]


if __name__ == "__main__":
    target_ip = sys.argv[1]
    nMap(target_ip)