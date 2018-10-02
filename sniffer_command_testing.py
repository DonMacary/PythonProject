#!/usr/bin/python
#
# Simplest Form Of Packet sniffer in python
# Works On Linux Platform 
 
import socket 
import struct
import binascii
import os
import datetime

# Ethernet Header
def eth_header(data):
    storeobj = data
    storeobj = struct.unpack("!6s6sH", storeobj)
    destination_mac = binascii.hexlify(storeobj[0])
    source_mac = binascii.hexlify(storeobj[1])
    eth_protocol = storeobj[2]
    data = {"Destination Mac": destination_mac,
            "Source Mac": source_mac,
            "Protocol": eth_protocol}
    return data

# ICMP Header
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
def ip_header(data):
    storeobj = struct.unpack("!BBHHHBBH4s4s", data)
    ip_version = storeobj[0]
    ip_tos = storeobj[1]
    ip_total_length = storeobj[2]
    ip_identification = storeobj[3]
    ip_fragment_offset = storeobj[4]
    ip_ttl = storeobj[5]
    ip_protocol = socket.getservbyport(storeobj[6])
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
            "Offset &amp; Reserved": tcp_offset_reserved,
            "Tcp Flag": tcp_flag,
            "Window": tcp_window,
            "CheckSum": tcp_checksum,
            "Urgent Pointer": tcp_urgent_pointer}
    return data

# UDP Header
def udp_header(self, data):
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

def print_column_titles():
    file_log.write("\n\n[+[ ----------------------- Macary Madness --------------------------[+]\n{} | {} | {} | {} | {} | {} | {} |".format(" No.", 
    "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information"))


#create an INET, raw socket
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

line_num = 1

# receive a packet
while True:
    # print output on terminal
    pkt=s.recvfrom(65565)
    file_log = open("packets.log", "a")
    current_date = str(datetime.datetime.now())
    file_log.write("\n{}".format(current_date)) 
    file_log.write(" ----------")


    
    print "\n\n[+] ------------ IP Header ------------[+]"
    for i in ip_header(pkt[0][14:34]).iteritems():
        a, b = i

        if line_num % 30 == 0:
            print_column_titles()
            print "\n\n[+[ ----------------------- Macary Madness --------------------------[+]"
            print "{} | {} | {} | {} | {} | {} | {} |".format(" No.", 
            "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")

        if a == "Version":
            continue
        elif a == "Identfication":
            continue
        else:
            file_log.write(" {:15} |".format(b)),
            print "{} : {} | ".format(a, b)
        
    line_num += 1

    file_log.close()
