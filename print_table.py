#This file will contain the functionality to print a table from a file
from report import *
from string import *
from ipprotoconvert import *

def displayTable():
    #open file
    input_file = open(raw_input("Type the file you would like to open.\n"), 'rU')
    print "\n\n  [+] ------------------------------- Macary Madness ------------------------------ [+]"
    print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(" No.", 
    "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
    data = input_file.readlines()
    for y in range(len(data)):
        sourceData = data[y].split(' ')
        sourceIP = sourceData[5]
        destIP = sourceData[14]
        protocol = protoName(int(sourceData[8]))
        length = sourceData[6]
        info = sourceData[13]

        print (" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format((y+1), (data[y][11:19]),sourceIP,
        destIP, protocol, length, info)
    input_file.close()