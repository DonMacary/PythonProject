#This function will display the table while listening

from shared_headers import ip_header
from ipprotoconvert import *
import collections
import time

def display_table(data, parsed_packet_db):
    line_num = 0
    if len(parsed_packet_db) > 0:
        for item in parsed_packet_db:
            if item["No."] > line_num:
                line_num = item["No."]
    line_num += 1

    if line_num % 50 == 0:
        print("\n\n  [+] ------------------------------- Macary Madness"),
        print("------------------------------ [+]")
        print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(" No.", 
            "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
    else:
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