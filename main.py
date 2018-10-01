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

test_sniffer = __import__("test-sniffer")
def check_int():
    #ask for user input and check if it's an integer
    user_input = raw_input("What would you like to do?\n")
    try:
        user_input = int(user_input)
    except ValueError:
        print ("Please input a valid response.")
        user_input = check_int()
    return user_input

def searchPackets():
    # the search functionality will go here
    # in the meantime here's a placeholder
    print("Congratulations! You have choosen to search!")
    print("Actual functionality will go here later!")

def enumeratePacket():
    # the enumerate functionality will go here
    # in the meantime here's a placeholder
    print("Congratulations! You have choosen to enumerate a packet!")
    print("This will give more details about a packet!")
    print("Actual functionality will go here later!")

def printTables():
    # the print table from file functionality will go here
    # in the meantime here's a placeholder
    print("Congratulations! You have choosen to print tables!")
    print("This will print a table with details about packets!")
    print("Actual functionality will go here later!")

# main menu
# set a variable to keep the menu running
runMenu = True
while (runMenu == True):
    print("1. Listen")
    print("2. Archive Search")
    print("3. Enumerate")
    print("4. Print Table from File")
    print("5. Quit")
    userInput = check_int()
    if (userInput == 1):
        test_sniffer.listening()
    elif (userInput == 2):
        searchPackets()
    elif (userInput == 3):
        enumeratePacket()
    elif (userInput == 4):
        printTables()
    elif (userInput == 5):
        print("Have a good day!\n")
        runMenu = False