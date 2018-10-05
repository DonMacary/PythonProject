#!/usr/bin/python
#
# Simplest Form Of Packet sniffer in python
# Works On Linux Platform 
 
import socket 
import struct
import binascii
import os
import datetime
from shared_headers import *
from report import *
import psutil

# Function that builds the file name to be used for packet information storage
def buildFileName():
    file_choice = ''
    while True:
        log_file = False
        for item in os.listdir(os.getcwd()):
            if ".log" in item:
                log_file = True
        if log_file is False:
            print("No previous log file detected.  Creating new logfile")
            file_choice = 'N'
            break
        else:
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
    if file_choice.upper() == 'N':
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
    if file_choice.upper() == 'L':
        year = 0
        month = 0
        day = 0
        version = 0
        list_of_files = os.listdir(os.getcwd())
        # This loop will go through all files within the current directory
        for item in list_of_files:
            parts = item.split(".")
            # Only files that end with *.log will be looked at
            if parts[len(parts) - 1] == 'log':
                # If the file starts with a year and is greater than the stored
                # year, store the new year value
                if int(item.split("_")[0]) > year:
                    year = int(item.split("_")[0])
                # If the year value matchs the max value held, continue looking
                # at the month and day
                if int(item.split("_")[0]) == year:
                    if int(item.split("_")[1]) > month:
                        month = int(item.split("_")[1])
                    if int(item.split("_")[1]) == month:
                        if int(item.split("_")[2]) > day:
                            day = int(item.split("_")[2])
                        if int(item.split("_")[2]) == day:
                            # If the loop has gotten this far, a packet log file
                            # exists as a most current build
                            # Since the use wants to have a new log file
                            # a version number will be added until a new file
                            # can be created
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
    for i in ip_header(data[0][14:34]).iteritems():
        a, b = i
        file_log.write(str(b) + " ")
        if a is "Protocol":
            next_op = b
    if next_op == 1:
        for i in icmp_header(data[0][34:38]).iteritems():
            a, b = i
            file_log.write(str(b) + " ")
    elif next_op == 6:
        for i in tcp_header(data[0][34:54]).iteritems():
            a, b = i
            file_log.write(str(b) + " ")
    elif next_op == 17:
        for i in udp_header(data[0][34:42]).iteritems():
            a, b = i
            file_log.write(str(b) + " ")
    file_log.write("\n")
    file_log.close()
    
def socket_choice(listLength):
    #ask for user input and check if it's an integer
    print("{:_^20}").format("")
    user_input = raw_input("Which socket would you like to listen on?\n")
    try:
        user_input = int(user_input)
        user_input <= listLength
        user_input > 0
    except ValueError:
        print ("Please input a valid response.")
        user_input = check_int()
    return user_input

def listening():
    print("------------------")
    print("Interfaces")
    print("------------------")
    #get network address types
    netList = psutil.net_if_addrs()
    #create a list object to assign the network address types to
    keyList = ["any"]
    #loop through and print out the list of network address types
    #append the address types to the list
    for i in range(len(netList)):
        keyList.append(netList.keys()[i])

    for i in range(len(keyList)):
        print "{}: {}".format(i+1,keyList[i])
    
    #let user choose which network address type
    userChoice = socket_choice(len(netList))
    if userChoice == 1:
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    else:
        keyChoice = keyList[userChoice-1]
        socketBind = keyChoice

        #create an INET, raw socket
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        #bind to the user's selected type
        s.bind((socketBind, 0x0800))

    logfile = buildFileName()
    # receive a packet
    raw_packet_db = []
    parsed_packet_db = []
    line_num = 1
    while True:
        try:
            # print output on terminal            
            pkt = s.recvfrom(65565)
            raw_packet_db.append(pkt)
            writeToLog(pkt, logfile)
            display_table(pkt, parsed_packet_db, line_num)
            line_num += 1
        except KeyboardInterrupt:
            break
    return raw_packet_db, parsed_packet_db
