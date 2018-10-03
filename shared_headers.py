#This file will contain all of the shared header functions

import struct
import socket 
import binascii
import os
import datetime
# Ethernet Header
# Return a dictionary of all elements within an Ethernet Header
def eth_header(data):
    storeobj = data
    storeobj = struct.unpack("!6s6sH", storeobj)
    destination_mac = binascii.hexlify(storeobj[0])
    source_mac = binascii.hexlify(storeobj[1])
    eth_protocol = hex(storeobj[2])
    # Outputs the mac addresses as standard Hex output with : notation
    destination_mac = ":".join([destination_mac[i:i + 2] 
        for i in range(0, len(destination_mac), 2)])
    source_mac = ":".join([source_mac[i:i + 2] 
        for i in range(0, len(source_mac), 2)])
    data = {"Destination Mac": destination_mac,
            "Source Mac": source_mac,
            "Protocol": eth_protocol}
    return data

# ICMP Header
# Return a dictionary of all elements within an ICMP Header
def icmp_header(data):
    icmph = struct.unpack('!BBH', data)
    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]
    data = {'ICMP Type': icmp_type,
            "Code": code,
            "CheckSum": checksum}
    return data

# IP Header
# Return a dictionary of all elements within an IP Header
def ip_header(data):
    storeobj = struct.unpack("!BBHHHBBH4s4s", data)
    ip_version = storeobj[0]
    ip_tos = storeobj[1]
    ip_total_length = storeobj[2]
    ip_identification = storeobj[3]
    ip_fragment_offset = storeobj[4]
    ip_ttl = storeobj[5]
    ip_protocol = storeobj[6]
    ip_header_checksum = storeobj[7]
    ip_source_address = socket.inet_ntoa(storeobj[8])
    ip_destination_address = socket.inet_ntoa(storeobj[9])
    data = {'Version': ip_version,
            'Tos': ip_tos,
            'Total Length': ip_total_length,
            'Identfication': ip_identification,
            'Fragment': ip_fragment_offset,
            'TTL': ip_ttl,
            'Protocol': ip_protocol,
            'Header Checksum': ip_header_checksum,
            'Source Address': ip_source_address,
            'Destination Address': ip_destination_address}
    return data

# TCP Header
# Return a dictionary of all elements within an TCP Header
def tcp_header(data):
    storeobj = struct.unpack('!HHLLBBHHH',data)
    tcp_source_port = storeobj[0]
    tcp_destination_port = storeobj[1]
    tcp_sequence_number = storeobj[2]
    tcp_acknowledge_number = storeobj[3]
    tcp_offset_reserved = storeobj[4]
    tcp_flag = storeobj[5]
    tcp_window = storeobj[6]
    tcp_checksum = storeobj[7]
    tcp_urgent_pointer = storeobj[8]
    data = {"Source Port": tcp_source_port,
            "Destination Port": tcp_destination_port,
            "Sequence Number": tcp_sequence_number,
            "Acknowledge Number": tcp_acknowledge_number,
            "Offset & Reserved": tcp_offset_reserved,
            "Tcp Flag": tcp_flag,
            "Window": tcp_window,
            "CheckSum": tcp_checksum,
            "Urgent Pointer": tcp_urgent_pointer}
    return data

# UDP Header
# Return a dictionary of all elements within an UDP Header
def udp_header(data):
    storeobj = struct.unpack('!HHHH', data)
    udp_source_port = storeobj[0]
    udp_dest_port = storeobj[1]
    udp_length = storeobj[2]
    udp_checksum = storeobj[3]
    data = {"Source Port": udp_source_port,
            "Destination Port": udp_dest_port,
            "Length": udp_length,
            "CheckSum": udp_checksum}
    return data

def check_int():
    #ask for user input and check if it's an integer
    user_input = raw_input("What would you like to do?\n")
    try:
        user_input = int(user_input)
    except ValueError:
        print ("Please input a valid response.")
        user_input = check_int()
    return user_input
