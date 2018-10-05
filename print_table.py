#This file will contain the functionality to print a table from a file
from shared_headers import *

def displayTable():
    """This function lets the user open a packet log and display the data from that log on the terminal"""
    itter = 1
    while itter == 1:
        try:
            ###############################
            #open file based on user input#
            ###############################
            input_file = open(raw_input("Type the file you would like to open.\n"), 'rU')
            itter = 2
        except KeyboardInterrupt:
            #If the user uses a keyboard interrupt, break out of the loop
            break
        except:
            #If the user inputs a filename that doesn't exist, let them know the filename was invalid
            print("Invalid File Name.  Please try again.")
    if (itter == 2):
        #print table header
        print "\n\n  [+] ------------------------------- Macary Madness ------------------------------ [+]"
        print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(" No.", 
        "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
        #read data from file
        data = input_file.readlines()
        #loop through and display data read from file
        for y in range(len(data)):
            sourceData = data[y].split(' ')
            sourceIP = sourceData[13]
            destIP = sourceData[14]
            protocol = protoName(int(sourceData[11]))
            length = sourceData[7]
            info = sourceData[12]

            print (" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format((y+1), (data[y][11:19]),sourceIP,
            destIP, protocol, length, info)
        ################
        #close the file#
        ################
        input_file.close()