import sys

from multiprocessing import Pool
from scapy.all import (Ether, ARP, srp)

def get_subnet(ip: str) -> str:
    """Get the subnet of the target IP address
    
    :param ip: The target IP address
    :return: The subnet of the target IP address
    """
    splitted_ip = ip.split(".")
    return f"{splitted_ip[0]}.{splitted_ip[1]}.{splitted_ip[2]}"

def get_device_adresses(ip: str, printing: bool = False) -> tuple[str, str] | None:
    """Get the MAC address of the target IP address using ARP request
    
    :param ip: The target IP address
    :param printing: Whether to print the output
    :return: A tuple of the target IP address and its MAC address
    """
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=ip)
    print("[*]Sending ARP request to", ip) if printing else None
    answered, _ = srp(packet, timeout=2, retry= 0, verbose=False)
    for _, r in answered:
        print(f"[+]A device responded : {r[ARP].psrc}, {r[Ether].src}") # prsc is the IP address of the target that responded to the ARP request
        return r[ARP].psrc, r[Ether].src
    print(f"[-]No device responded") if printing else None

def nMap(ip: str) -> list[str] | None:
    """Scan the subnet for all devices
    
    :param ip: The target IP address
    :return: A list of devices found in the subnet
    """
    print("[*]Scanning the subnet for all devices...")
    with Pool(processes=254) as pool:
        result = pool.map(get_device_adresses, [f"{get_subnet(ip)}.{i}" for i in range(1, 255)])
    pool.join()
    print("[*]Scan completed")
    if len(result) == 0:
        print("[-]No devices found")
        return
    return [addr for addr in result if addr is not None]


if __name__ == "__main__":
    target_ip = sys.argv[1]
    nMap(target_ip)