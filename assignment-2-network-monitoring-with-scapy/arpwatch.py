import argparse
from scapy.all import *
import subprocess
import netaddr
import socket
import struct
import threading
import time


def get_arp_table():
    """Gets the current ARP table entries."""
    arp_output = subprocess.check_output(['arp', '-a']).decode()
    arp_table = {}

    for line in arp_output.splitlines():
        fields = line.split() 
        # Handle for Linux
        if len(fields) >= 4 and fields[2] == 'at':
            ip = fields[1][1 : len(fields[1]) - 1]
            mac = fields[3]
            arp_table[ip] = mac
        # Handle for Windows
        elif len(fields) >= 3 and fields[2] == 'dynamic':
            ip = fields[0]
            mac = fields[1]
            arp_table[ip] = mac
    # print("ARP Table:")
    # for ip, mac in arp_table.items():
    #     print(f"{ip} -> {mac}")
    return arp_table

def arp_monitor_callback(pkt):
    """Callback function for the ARP monitor."""
    if pkt[ARP].op in (1, 2):  # who-has (request) or is-at (response)
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"ARP Cache Poisoning Alert: {ip} changed from {arp_table[ip]} to {mac}")
        
def check_arp_changes():
    """Periodically checks for ARP table changes."""
    global arp_table
    while True:
        try:
            new_arp_table = get_arp_table()   

            # Compare old and new tables
            for ip, old_mac in arp_table.items():
                if ip in new_arp_table:
                    if new_arp_table[ip] != old_mac:
                        print(f"ARP Cache Poisoning Alert: {ip} changed from {old_mac} to {new_arp_table[ip]}")

            arp_table = new_arp_table  # Update the global table
        except Exception as e:
            print(f"Error checking ARP changes: {e}")

        time.sleep(3)  # Check every 3 seconds

if __name__ == "__main__":
    """Main function to run the ARP monitor."""
    parser = argparse.ArgumentParser(description='ARP Cache Poisoning Detector')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface
    # try to read arp table from OS cache
    arp_table = get_arp_table()
    print("Initial ARP table:")
    for ip, mac in arp_table.items():
        print(f"{ip} -> {mac}")

    monitoring_thread = threading.Thread(target=check_arp_changes)
    monitoring_thread.daemon = True
    monitoring_thread.start()

    print("Monitoring for ARP cache changes...")
    sniff(prn=arp_monitor_callback, filter="arp", store=0) 