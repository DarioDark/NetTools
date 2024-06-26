import sys

def subnetCalculator(cidr: int) -> str:
    """Calculate the subnet mask for a given CIDR value."""
    if not 0 <= cidr <= 32:
        raise ValueError("CIDR value must be between 0 and 32")
    binary_string: str = "1" * cidr + "0" * (32 - cidr) # Create a binary string of 1s and 0s
    byte_list :list[str] = [binary_string[i:i+8] for i in range(0, 32, 8)] # Convert the binary string to a list of 4 octets
    subnet: str = ".".join(list(str(int(byte, 2)) for byte in byte_list)) # Convert the binary numbers to decimal numbers and join them with a dot
    return f"Subnet : {subnet}\nNumber of hosts : {2**(32-cidr)-2}"


if __name__ == "__main__":
    cidr: int = int(sys.argv[1])
    print(calc_subnet(cidr))
