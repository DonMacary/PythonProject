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

def searchPackets():
    # the search functionality will go here
    # in the meantime here's a placeholder
    print("Congratulations! You have choosen to search!")
    print("Actual functionality will go here later!")

def printTables():
    # the print table from file functionality will go here
    # in the meantime here's a placeholder
    print("Congratulations! You have choosen to print tables!")
    print("This will print a table with details about packets!")
    print("Actual functionality will go here later!")

# main menu
# set a variable to keep the menu running
def MacaryMadness():

    runMenu = True
    enum_db = []

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
            enum_db = listening()
        elif (userInput == 2):
            searchPackets()
        elif (userInput == 3):
            packetChoice(enum_db)
        elif (userInput == 4):
            printTables()
        elif (userInput == 5):
            print("{:_^20}").format("")
            print("Have a good day!\n")
            print("{:_^20}").format("")
            break
        else:
            print("{:_^20}").format("")
            print("That was not a valid option.")
            print("{:_^20}").format("")

if __name__ == "__main__":
    MacaryMadness()