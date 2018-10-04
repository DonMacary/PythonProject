#This file will contain all of the shared header functions

import struct
import socket 
import binascii
import os
import datetime
import collections
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
    data = collections.OrderedDict()
    data["Destination Mac"] = destination_mac
    data["Source Mac"] = source_mac
    data["Protocol"] = eth_protocol
    return data

# ICMP Header
# Return a dictionary of all elements within an ICMP Header
def icmp_header(data):
    icmph = struct.unpack('!BBH', data)
    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]
    data = collections.OrderedDict()
    data["ICMP Type"] = icmp_type
    data["Code"] = code
    data["Checksum"] = checksum
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
    data = collections.OrderedDict()
    data["Version"] = ip_version
    data["Tos"] = ip_tos
    data["Total Length"] = ip_total_length
    data["Identification"] = ip_identification
    data["Fragment"] = ip_fragment_offset
    data["TTL"] = ip_ttl
    data["Protocol"] = ip_protocol
    data["Header Checksum"] = ip_header_checksum
    data["Source Address"] = ip_source_address
    data["Destination Address"] = ip_destination_address
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
    data = collections.OrderedDict()
    data["Source Port"] = tcp_source_port
    data["Destination Port"] = tcp_destination_port
    data["Sequence Number"] = tcp_sequence_number
    data["Acknowledge Number"] = tcp_acknowledge_number
    data["Offset & Reserved"] = tcp_offset_reserved
    data["Tcp Flag"] = tcp_flag
    data["Window"] = tcp_window
    data["CheckSum"] = tcp_checksum
    data["Urgent Pointer"] = tcp_urgent_pointer
    return data

# UDP Header
# Return a dictionary of all elements within an UDP Header
def udp_header(data):
    storeobj = struct.unpack('!HHHH', data)
    udp_source_port = storeobj[0]
    udp_dest_port = storeobj[1]
    udp_length = storeobj[2]
    udp_checksum = storeobj[3]
    data = collections.OrderedDict()
    data["Source Port"] = udp_source_port
    data["Destination Port"] = udp_dest_port
    data["Length"] = udp_length
    data["CheckSum"] = udp_checksum
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