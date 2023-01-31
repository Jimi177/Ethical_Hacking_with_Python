#!/usr/bin/env python

import requests, optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-l", "--link", dest="link", help="Please enter the link to download file")
    (options, arguments) = parser.parse_args()

    if not options.email:
        parser.error("[-] Please enter the link to download file --help for mor info.")

    return options

def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)

options = get_arguments()

download(options.link)
