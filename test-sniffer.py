#!/usr/bin/python
#
# Simplest Form Of Packet sniffer in python
# Works On Linux Platform 
 
import socket 
import struct
import binascii
import os
import datetime

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
 
#create an INET, raw socket
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
 
# receive a packet
while True:
    # print output on terminal
    pkt=s.recvfrom(65565)
    file_log = open("packets.log", "a")
    current_date = str(datetime.datetime.now())
    file_log.write(current_date) 
    file_log.write(" ----------")
    
    print "\n\n[+] ------------ IP Header ------------[+]"
    for i in ip_header(pkt[0][14:34]).iteritems():
        a, b = i
        file_log.write("{} : {} |".format(a, b))
        print "{} : {} | ".format(a, b)
    file_log.close()
