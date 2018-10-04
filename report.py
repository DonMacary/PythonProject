#This function will display the table while listening

from shared_headers import ip_header
from ipprotoconvert import *
import collections
import time

def display_table(data, parsed_packet_db, line_num):
    if line_num % 50 == 0:
        print("\n\n  [+] ------------------------------- Macary Madness"),
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
            
        print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(
            rp_data["No."], rp_data["Time"], rp_data["Source Address"], 
            rp_data["Destination Address"], protoName(int(rp_data["Protocol"])), 
            rp_data["Total Length"], rp_data["Header Checksum"])
        parsed_packet_db.append(rp_data)
    return parsed_packet_db
