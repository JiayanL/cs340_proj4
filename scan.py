import sys
import json
import subprocess
from datetime import datetime
import re
import http.client
import socket
import requests
import maxminddb
import time
'''
Using subprocess module
Subprocess allows you to execute command line commands in python

Example:
    result = subprocess.check_output(["nslookup", "northwestern.edu", "8.8.8.8"],
                                     timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
'''
dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9",
                     "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7",
                     "156.154.70.1", "198.101.242.72", "176.103.130.130"]
max_retries = 1
local = True # just for local testing due to ipv6 format differences

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
    ip_pattern = r"Address:\s*(\d+\.\d+\.\d+\.\d+)"

    for resolver in dns_resolvers:
        for _ in range(max_retries):
            try:
                nslookup = subprocess.check_output(["nslookup", domain, resolver],
                                                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                addresses = re.findall(ip_pattern, nslookup)
                ipv4_addresses.extend(addresses)
            except subprocess.TimeoutExpired:
                print(f"Timeout expired for resolver {resolver}")
                continue
            except Exception as e:
                print(f"An error occurred: {e}")
                continue
            
    return list(set(ipv4_addresses))

def scan_ipv6(domain):
    ipv6_addresses = []
    ip_pattern = r"Address: ([0-9a-fA-F:]+)"

    for resolver in dns_resolvers:
        for _ in range(max_retries):
            try:
                nslookup = subprocess.check_output(["nslookup", "-type=AAAA", domain, resolver],
                                                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                addresses = re.findall(ip_pattern, nslookup)
                ipv6_addresses.extend(addresses)
            except subprocess.TimeoutExpired:
                print(f"Timeout expired for resolver {resolver}")
                continue
            except Exception as e:
                print(f"An error occurred: {e}")
                continue
            
    return list(set(ipv6_addresses))

def scan_http_server(domain):
    conn = http.client.HTTPConnection(domain, timeout=2)
    try:
        conn.request("GET", "/")
        response = conn.getresponse()
        server_header = response.getheader('Server')

        if server_header:
            return server_header
        else:
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    finally:
        conn.close()

def scan_insecure_http(domain):
    try:
        # create a socket (proj 2 / textbook)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        # attempt to connect to port 80
        sock.connect((domain, 80))
        sock.close()
        return True
    except Exception as e:
        # if it fails, then we couldn't connect
        print(f"An error ocurred: {e}")
        return False

def scan_redirect_to_https(domain):
    url = "http://" + domain
    try:
        session = requests.Session()
        session.max_redirects = 10
        # call in response
        response = session.get(url, allow_redirects=True, timeout=5)

        # check if final URL is https
        if response.url.startswith("https://"):
            return True
        else:
            return False
    except requests.exceptions.TooManyRedirects:
        print(f"Too many redirects for {domain}")
        return False
    except requests.ConnectionError: # edge case - no connection
        print(f"Connection error for {domain}")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def scan_rtt_range(ipv4_addresses):
    min_rtt = float('inf')
    max_rtt = float('-inf')
    common_ports = [80, 22, 443]
    for address in ipv4_addresses:
        for port in common_ports:
            try:
                # create a socket inspired by proj 2 / textbook
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)

                # time the connection
                start = time.time()
                sock.connect((address, port))
                end = time.time()

                # measure and log
                rtt = (end - start) * 1000
                min_rtt = min(min_rtt, rtt)
                max_rtt = max(max_rtt, rtt)
                print(f"rtt for {address} and port {port}: {rtt} ms")
                sock.close()
            except socket.timeout:
                print(f"Timeout occurred for {address} and port {port}")
                continue
            except Exception as e:
                print(f"An error occurred: {e}")
                continue
    if min_rtt == float('inf') or max_rtt == float('-inf'):
        return None
    return [min_rtt, max_rtt]

def scan_geo_locations(ipv4_addresses):
    results = []
    with maxminddb.open_database('GeoLite2-City.mmdb') as geo_db:
        for address in ipv4_addresses:
            try:
                response = geo_db.get(address)
                if response:
                    # get city
                    city = response.get('city', {}).get('names', {}).get('en')
                    if not city:
                        continue
                    # get state
                    state = response.get('subdivisions', [{}])[0].get('names', {}).get('en')
                    if not state:
                        continue
                    # get country
                    country = response.get('country', {}).get('names', {}).get('en')
                    if not country:
                        continue

                    geo_location = f"{city}, {state}, {country}".strip(",")
                    if geo_location:
                        results.append(geo_location)
            except Exception as e:
                print(f"An error occurred: {e}")
                continue
    return list(set(results))

def scan_rdns_names(ipv4_addresses):
    results = []
    ip_pattern = r"name\s*=\s*(.+)\."
    for address in ipv4_addresses:
        try:
            # inspired by hw code
            nslookup = subprocess.check_output(["nslookup", "-type=PTR", address],
                                                timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            rdns_names = re.findall(ip_pattern, nslookup)
            results.extend(rdns_names)
        except subprocess.TimeoutExpired:
            print(f"nslookup command timed out for {ip}")
        except Exception as e:
            print(f"An error occurred: {e}")
            continue
    return list(set(results))

def scan_domains(domains):
    result = {}
    for domain in domains:
        scan_time = datetime.now().timestamp()
        ipv4_addresses = scan_ipv4(domain)
        if local: # TODO: remove this eventually
            ipv6_addresses = []
        else:
            ipv6_addresses = scan_ipv6(domain)
        http_server = scan_http_server(domain)
        insecure_http = scan_insecure_http(domain)
        redirect_to_https = scan_redirect_to_https(domain)
        geo_locations = scan_geo_locations(ipv4_addresses)
        # rtt_range = scan_rtt_range(ipv4_addresses)
        rtt_range = 1 #TODO: remove
        rdns_names = scan_rdns_names(ipv4_addresses)

        result[domain] = {
            "scan_time": datetime.timestamp(datetime.now()),
            "ipv4_addresses": ipv4_addresses,
            "ipv6_addresses": ipv6_addresses,
            "http_server": http_server,
            "insecure_http": insecure_http,
            "redirect_to_https": redirect_to_https,
            "rdns_names": rdns_names,
            "rtt_range": rtt_range,
            "geo_locations": geo_locations,
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
