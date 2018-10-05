#This function will display the table while listening

from shared_headers import *
from ipprotoconvert import *
import collections
import time

def display_table(data, parsed_packet_db, line_num):
    
    if line_num % 50 == 0 or line_num == 1:
        print "\n\t\t\t\tPress Ctrl+C to exit listener"
        print("\n  [+] ------------------------------- Macary Madness"),
        print("------------------------------ [+]")
        print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(" No.", 
            "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
    if line_num > 0:
        dt = time.strftime("%H:%M:%S")
        rp_data = collections.OrderedDict()
        for i in ip_header(data[0][14:34]).iteritems():    
            a, b = i
            rp_data[a] = b
        rp_data["No."] = line_num
        rp_data["Time"] = dt
        if int(rp_data["Protocol"]) == 1:
            rp_data["Header Checksum"] = "ICMP Checksum: " 
            rp_data["Header Checksum"] += str(icmp_header(data[0][34:38])["Checksum"])
        if int(rp_data["Protocol"]) == 6:
            rp_data["Header Checksum"] = str(tcp_header(data[0][34:54])["Source Port"])
            rp_data["Header Checksum"] += " -> "
            rp_data["Header Checksum"] += str(tcp_header(data[0][34:54])["Destination Port"])
            flags = tcp_header(data[0][34:54])["Tcp Flag"]
            if flags >= 256:
                rp_data["Header Checksum"] += "[NS]"
                flags -= 256
            if flags >= 128:
                rp_data["Header Checksum"] += "[CWR]"
                flags -= 128
            if flags >= 64:
                rp_data["Header Checksum"] += "[ECE]"
                flags -= 64
            if flags >= 32:
                rp_data["Header Checksum"] += "[URG]"
                flags -= 32
            if flags >= 16:
                rp_data["Header Checksum"] += "[ACK]"
                flags -= 16
            if flags >= 8:
                rp_data["Header Checksum"] += "[PSH]"
                flags -= 8
            if flags >= 4:
                rp_data["Header Checksum"] += "[RST]"
                flags -= 4
            if flags >= 2:
                rp_data["Header Checksum"] += "[SYN]"
                flags -= 2
            if flags >= 1:
                rp_data["Header Checksum"] += "[FIN]"
            
        if int(rp_data["Protocol"]) == 17:
            rp_data["Header Checksum"] = str(udp_header(data[0][34:42])["Source Port"])
            rp_data["Header Checksum"] += " -> "
            rp_data["Header Checksum"] += str(udp_header(data[0][34:42])["Destination Port"])
 
        print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(
            rp_data["No."], rp_data["Time"], rp_data["Source Address"], 
            rp_data["Destination Address"], protoName(int(rp_data["Protocol"])), 
            rp_data["Total Length"], rp_data["Header Checksum"])
        parsed_packet_db.append(rp_data)
    return parsed_packet_db
