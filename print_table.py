#This file will contain the functionality to print a table from a file
from report import *

def displayTable():
    input_file = open(raw_input("Type the file you would like to open.\n"), 'rU')
    count = 0
    data = input_file.read(186)
    dataSplit = [data.split('2018')]
    
    while (count <= 25):
        print dataSplit[count]
        count += 1
        print ("Next count = {}").format(count)
    
    print "\n\n  [+] ------------------------------- Macary Madness ------------------------------ [+]"
    print " {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ".format(" No.", 
    "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
    print(" Working on formatting from file.")
    input_file.close()