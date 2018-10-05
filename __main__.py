"""
Project: Python Sniffer
Date: 1 Oct 2018

This is the main menu for the project. It will loop until the user
decides to quit. Functions will be called based on user input.

Current functions are:
1. Listen -- this will listen and receive packets
2. Archive Search -- this will allow you to search the packets
3. Enumerate -- this will give additional details about packets
4. Print Table from File -- this will give a report on the packets
5. Quit -- this will exit the program
"""

from listener import *
from enumPacket import *
from shared_headers import check_int
from print_table import *
from search_data import *

# main menu
# set a variable to keep the menu running
def MacaryMadness():

    runMenu = True
    enum_db = []
    parsed_packet_db = []

    while (runMenu == True):
        print("{:_^20}").format("")
        print("1. Listen")
        print("2. Archive Search")
        print("3. Enumerate")
        print("4. Print Table from File")
        print("5. Quit")
        print("{:_^20}").format("")
        userInput = check_int()
        if (userInput == 1):
            #this calls the listening function to let the user start listening on ports
            enum_db, parsed_packet_db = listening()
        elif (userInput == 2):
            #this calls the search_packets function to let the user search through packets
            search_packets(parsed_packet_db)
        elif (userInput == 3):
            #this calls the packetChoice function to let the user view more data about a packet
            if not enum_db:
                print "\nMust listen before enumeration"
            else:
                packetChoice(enum_db)
        elif (userInput == 4):
            #this calls the displayTable function to let the user input a log file to view the data from
            displayTable()
        elif (userInput == 5):
            #this exits the program
            print("{:_^20}").format("")
            print("Have a good day!\n")
            print("{:_^20}").format("")
            break
        else:
            #the user input something that was not listed on the menu
            print("{:_^20}").format("")
            print("That was not a valid option.")
            print("{:_^20}").format("")

if __name__ == "__main__":
    MacaryMadness()
