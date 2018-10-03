#This function will display the table while listening

from shared_headers import ip_header
from ipprotoconvert import *
import time

#Global variables
line_num = 0
packet_db = []

def display_table(data):
    global packet_db
    global line_num
    
    try:
        if line_num % 50 == 0:
            print "\n\n  [+] ------------------------------- Macary Madness ------------------------------ [+]"
            print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(" No.", 
            "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
        else:
            dt = time.strftime("%H:%M:%S")
            rp_data = {}
            for i in ip_header(data[0][14:34]).iteritems():    
                a, b = i
                rp_data[a] = b
            rp_data["Time"] = dt
            rp_data["No."] = line_num
                
            print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(rp_data["No."], 
            rp_data["Time"], rp_data["Source Address"], rp_data["Destination Address"], 
            protoName(rp_data["Protocol"]), rp_data["Total Length"], 
            rp_data["Header Checksum"])
            packet_db.append(rp_data)
        line_num += 1
    except KeyboardInterrupt:
        #This needs to be replaced with main() call after main is built
        exit(0)
        # main()
