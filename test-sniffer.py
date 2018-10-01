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

# Function that builds the file name to be used for packet information storage
def buildFileName():
    file_choice = ''
    while True:
        # User is prompted to either use a prior file or a new logfile
        print("Would you like to write to a new log file(N)"),
        user_input = raw_input("or the last one(L)?:::")
        if user_input.upper() != 'N' and user_input.upper() != 'L':
            print("User input is not valid.  Please choose again.")
        else:
            file_choice = user_input
            break
    full_file_name = ""
    packet_version = 1
    # If a new file is used, the file name will be based on the date
    # If a version of the file is detected, then a number is appended
    # to the end of the file
    if file_choice == 'N':
        file_name = str(datetime.datetime.today().year) + "_"
        file_name += str(datetime.datetime.today().month) + "_"
        file_name += str(datetime.datetime.today().day)
        file_ext =  "_packet.log"
        list_of_files = os.listdir(os.getcwd())
        full_file_name = file_name + file_ext
        while full_file_name in list_of_files:
            full_file_name = file_name + "_(" + str(packet_version) + ")"
            full_file_name += file_ext
            packet_version += 1
        file_write = open(full_file_name, "w+")
        file_write.close()
    # If the last log file is used, then the most current file needs to be 
    # determined from the list of log files
    if file_choice == 'L':
        year = 0
        month = 0
        day = 0
        version = 0
        list_of_files = os.listdir(os.getcwd())
        for item in list_of_files:
            parts = item.split(".")
            if parts[len(parts) - 1] == 'log':
                if int(item.split("_")[0]) > year:
                    year = int(item.split("_")[0])
                if int(item.split("_")[0]) == year:
                    if int(item.split("_")[1]) > month:
                        month = int(item.split("_")[1])
                    if int(item.split("_")[1]) == month:
                        if int(item.split("_")[2]) > day:
                            day = int(item.split("_")[2])
                        if int(item.split("_")[2]) == day:
                            if "packet" not in item.split("_")[3]:
                                version = item.split("_")[3]
        full_file_name = str(year) + "_" + str(month) + "_" + str(day) + "_" + version
        full_file_name += "_packet.log"
    return full_file_name

# Using the built file name, all packet information will be written to it
def writeToLog(data, logfile):
    file_log = open(logfile, "a")
    current_date = str(datetime.datetime.now())
    file_log.write(current_date) 
    file_log.write(" ----------")
    next_op = ""

    # Each header will be written to the log file
    for header in eth_header(data[0][0:14]).iteritems():
        a, b = header
        file_log.write(str(b) + " ")
    for i in ip_header(pkt[0][14:34]).iteritems():
        a, b = i
        file_log.write(str(b) + " ")
        if a is "Protocol":
            next_op = b
    if next_op == 1:
        for i in icmp_header(pkt[0][34:38]).iteritems():
            a, b = i
            file_log.write(str(b) + " ")
    elif next_op == 6:
        for i in tcp_header(pkt[0][34:54]).iteritems():
            a, b = i
            print("{} : {} |").format(a, b)
            file_log.write(str(b) + " ")
    elif next_op == 17:
        for i in udp_header(pkt[0][34:42]).iteritems():
            a, b = i
            file_log.write(str(b) + " ")
    file_log.close()


#create an INET, raw socket
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

logfile = buildFileName()
# receive a packet
while True:
    # print output on terminal
    pkt = s.recvfrom(65565)
    writeToLog(pkt, logfile)
