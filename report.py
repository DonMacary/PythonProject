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

    if line_num % 50 == 0:
        print "\n\n  [+] ------------------------------- Macary Madness ------------------------------ [+]"
        print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(" No.", 
        "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
    else:
        dt = time.strftime("%H:%M:%S")
        #TODO: change rp_data to parsed_packet_db
        rp_data = []
        for i in ip_header(data[0][14:34]).iteritems():    
            a, b = i
            rp_data.append(b)     
        rp_data.insert(0, line_num)
        rp_data.insert(1, dt)
            
        print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(rp_data[0], 
        rp_data[1], rp_data[2], rp_data[11], 
        protoName(rp_data[5]), rp_data[3], 
        rp_data[10])
        packet_db.append(rp_data)
    line_num += 1
    return packet_db
       

