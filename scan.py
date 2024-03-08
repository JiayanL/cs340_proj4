import sys
import json
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

def scan_domains(domains):
    result = {}
    for domain in domains:
        scan_time = datetime.now().timestamp()
        result[domain] = {
            "scan_time": datetime.timestamp(datetime.now())
        }
    return result

if __name__ == "__main__":
    read_file = sys.argv[1]
    write_file = sys.argv[2]

    domains = read_domains(read_file)

    results = scan_domains(domains)
    
    with open(write_file, 'w') as file:
        json.dump(results, file, sort_keys=True, indent=4)
