import os
import socket
import subprocess
import scapy.all as scapy
from datetime import datetime

# Function to check if a device is online by pinging the IP address
def ping_ip(ip):
    print(f"Pinging {ip} to check if it's online...")
    response = os.system(f"ping -c 1 {ip}")
    if response == 0:
        print(f"[+] {ip} is online.")
    else:
        print(f"[-] {ip} is offline or unreachable.")

# Function to scan open ports using socket
def scan_ports(ip):
    print(f"Scanning ports on {ip}...")
    open_ports = []
    for port in range(1, 65535):  # Scanning all ports (from 1 to 65535)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout for each connection attempt
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        print(f"[+] Open ports on {ip}: {open_ports}")
    else:
        print(f"[-] No open ports found on {ip}.")

# Function to scan for active devices on the local network (ARP scan)
def scan_network(network):
    print(f"Scanning the network: {network}")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("\n[+] Devices on the network:")
    for element in answered_list:
        print(f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}")

# Function to check if a specific service is running (e.g., SSH, HTTP)
def check_service(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"[+] Service running on {ip}:{port}")
    else:
        print(f"[-] No service running on {ip}:{port}")
    sock.close()

# Main function to troubleshoot a computer remotely
def troubleshoot(ip):
    print("\nStarting troubleshooting process...\n")
    print(f"Scanning started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check if the IP address is online
    ping_ip(ip)
    
    # Scan for open ports
    scan_ports(ip)

    # Check if common services are running (e.g., SSH, HTTP, FTP)
    services_to_check = [22, 80, 443, 21]  # SSH, HTTP, HTTPS, FTP
    for port in services_to_check:
        check_service(ip, port)

    print(f"\nTroubleshooting completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

if __name__ == "__main__":
    target_ip = input("Enter the IP address of the computer to troubleshoot: ")
    
    # Network scan for local network
    network_scan = input("Do you want to scan the local network for devices? (y/n): ")
    if network_scan.lower() == 'y':
        network = input("Enter your network (e.g., 192.168.1.0/24): ")
        scan_network(network)
    
    # Troubleshoot the specified IP
    troubleshoot(target_ip)
