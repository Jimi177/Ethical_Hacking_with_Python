#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target", help="Select target ip")
    options= parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify an ip target, use --help for mor info.")

    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list=[]

    for element in answered_list:
        clients_dict = {"ip":element[1].psrc, "mac":element[1].hwdst}
        clients_list.append(clients_dict)

    return clients_list

def print_resault(resaults_list):
    print("IP\t\t\tMAC Adress\n------------------------------------------")
    for client in resaults_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_resault = scan(options.target)
print_resault(scan_resault)