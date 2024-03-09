import sys
import json
import http.client
import ssl
import re
import subprocess
'''
Using subprocess module
Subprocess allows you to execute command line commands in python

Example:
    result = subprocess.check_output(["nslookup", "northwestern.edu", "8.8.8.8"],
                                     timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
'''
from datetime import datetime

def read_domains(file):
    with open(file, 'r') as file:
        return [line.strip() for line in file.readlines()]

def check_hsts(domain):
    try:
        conn = http.client.HTTPSConnection(domain, timeout=5, context=ssl.create_default_context())
        conn.request("HEAD", "/")
        response = conn.getresponse()
        headers = response.getheaders()
        for header in headers:
            if header[0].lower() == "strict-transport-security":
                return True
        return False
    except:
        print("Error checking for HSTS")
        return False

def get_tls_versions(domain):
    supported_versions = []
    try:
        command = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", domain]
        result = subprocess.check_output(command, timeout=20, stderr=subprocess.STDOUT).decode('utf-8')
        if "SSLv2" in result:
            supported_versions.append("SSLv2")
        if "SSLv3" in result:
            supported_versions.append("SSLv3")
        if "TLSv1.0" in result:
            supported_versions.append("TLSv1.0")
        if "TLSv1.1" in result:
            supported_versions.append("TLSv1.1")
        if "TLSv1.2" in result:
            supported_versions.append("TLSv1.2")
    except:
        print("Error with TLS nmap")
    
    try:
        command = ['openssl', 's_client', '-tls1_3', '-connect', f'{domain}:443']
        result = subprocess.check_output(command, input=b'', timeout=20, stderr=subprocess.STDOUT).decode('utf-8')
        if "TLSv1.3" in result:
            supported_versions.append("TLSv1.3")
    except:
        print("Error with TLS openssl")

    return supported_versions

def get_root_ca(domain):
    try:
        command = ['openssl', 's_client',
            '-connect', f'{domain}:443',
            '-servername', domain,
            '-showcerts']
        result = subprocess.check_output(command, input=b'', stderr=subprocess.STDOUT).decode('utf-8')
        matches = list(re.finditer(r'O\s?=\s?([^\n,]*)(?:,|$)', result))
        if matches:
            return matches[-1].group(1).strip()
        return None
    except:
        print("Error on root ca")
        return None

def scan_domains(domains):
    result = {}
    for domain in domains:
        scan_time = datetime.now().timestamp()
        result[domain] = {
            "scan_time": datetime.timestamp(datetime.now()),
            "hsts": check_hsts(domain),
            "tls_versions": get_tls_versions(domain),
            "root_ca": get_root_ca(domain),
        }
    return result

if __name__ == "__main__":
    read_file = sys.argv[1]
    write_file = sys.argv[2]

    domains = read_domains(read_file)

    results = scan_domains(domains)
    
    with open(write_file, 'w') as file:
        json.dump(results, file, sort_keys=True, indent=4)
