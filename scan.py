import sys
import json
import subprocess
from datetime import datetime
import re
'''
Using subprocess module
Subprocess allows you to execute command line commands in python

Example:
    result = subprocess.check_output(["nslookup", "northwestern.edu", "8.8.8.8"],
                                     timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
'''

#
# Helper Functions
#
def read_domains(file):
    with open(file, 'r') as file:
        return [line.strip() for line in file.readlines()]

#
# Scan Functions
#
def scan_ipv4(domain):
    ipv4_addresses = []
    dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9",
                     "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7",
                     "156.154.70.1", "198.101.242.72", "176.103.130.130"]
    ip_pattern = r"Address:\s*(\d+\.\d+\.\d+\.\d+)"

    for resolver in dns_resolvers:
        try:
            nslookup = subprocess.check_output(["nslookup", "northwestern.edu", resolver],
                                            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            addresses = re.findall(ip_pattern, nslookup)
            ipv4_addresses = ipv4_addresses + addresses
            break
        except subprocess.TimeoutExpired:
            continue

    return list(set(ipv4_addresses))


def scan_domains(domains):
    result = {}
    for domain in domains:
        scan_time = datetime.now().timestamp()
        ipv4_addresses = scan_ipv4(domain)

        result[domain] = {
            "scan_time": datetime.timestamp(datetime.now()),
            "ipv4_addresses": ipv4_addresses,
        }

    return result

#
# Main
# 
if __name__ == "__main__":
    read_file = sys.argv[1]
    write_file = sys.argv[2]

    domains = read_domains(read_file)

    results = scan_domains(domains)
    print(results)
    
    with open(write_file, 'w') as file:
        json.dump(results, file, sort_keys=True, indent=4)
