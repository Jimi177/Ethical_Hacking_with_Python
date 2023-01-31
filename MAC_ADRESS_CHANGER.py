#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC adress")
    parser.add_option("-m", "--mac", dest="newMacAdress", help="New MAC adress")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for mor info.")
    elif not options.newMacAdress:
        parser.error("[-] Please specify n new MAC adress, use --help for mor info.")

    return options

def change_mac(interface, newMacAdress):
    print("[+] Changing MAC adress for " + interface + " to " + newMacAdress)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", newMacAdress])
    subprocess.call(["ifconfig", interface, "up"])

def get_currnt_mac(interface):
    ifconfigResult = subprocess.check_output(["ifconfig", interface])
    macAdressSearchResault = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfigResult))

    if macAdressSearchResault:
        return macAdressSearchResault.group(0)
    else:
        print("[-] I couldnt read MAC adress")

options = get_arguments()

current_mac = get_currnt_mac(options.interface)
print("Current MAC = "+ str(current_mac))

change_mac(options.interface, options.newMacAdress)
current_mac = get_currnt_mac(options.interface)

if current_mac == options.newMacAdress:
    print("[+] MAC adress was successfully changet to " + current_mac)
else:
    print("[-] MAC adress didnt get changed")

