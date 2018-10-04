#Function will take in a packet and print the data
from shared_headers import *

def onePacket():
    #ask for user input and check if it's an integer
    print "\nReady to select individual packet"
    user_input = raw_input("Enter the packet number: \n").rstrip()
    try:
        user_input = int(user_input)
    except ValueError:
        print ("Please input a valid response.")
        user_input = onePacket()
    return user_input

#Select start of range
def rangeStart():
    packStart = raw_input("Enter starting packet number: ").rstrip()
    #packEnd = raw_input("Enter ending packet number: ").rstrip()
    try:
       packStart = int(packStart)
    except ValueError:
        print ("Please input a valid response.")
        packStart = rangeStart()
    return int(packStart)

#Select end of range
def rangeEnd():
    packEnd = raw_input("Enter ending packet number: ").rstrip()
    try:
       packEnd = int(packEnd)
    except ValueError:
        print ("Please input a valid response.")
        packEnd = rangeEnd()
    return int(packEnd)

#Allows for combination of single packet and range of packet selection
def multiplePackets():
    print "\nReady for packet selection"
    user_input = raw_input("Enter packet number and/or packet number range: ").rstrip()
    try:
        packRange = user_input.split(" `-=\][';/.,~!@#$%^&*()_+|}{:?><")
        for i in range(len(packRange)):
            packRange[i] = int(packRange[i])
    except ValueError:
        print ("Please input a valid response.")
        user_input = multiplePackets()
    return packRange

def enumeratePacket(data):
    temp_db = []
    #Ethernet Header
    print "\n--------------------------------"
    print "-------- ETHERNET HEADER -------"
    print "--------------------------------"
    for i in eth_header(data[0][0:14]).iteritems():    
        a, b = i
        print "{} : {} ".format(a,b)

    #IP Header 
    print "\n--------------------------------"
    print "----------- IP HEADER ----------"
    print "--------------------------------"
    for i in ip_header(data[0][14:34]).iteritems():    
        a, b = i
        temp_db.append(b)
        print "{} : {} ".format(a,b)

    #Checks if TCP protocol
    if temp_db[3] == 6:    
        #TCP Header
        print "\n--------------------------------"
        print "----------- TCP HEADER ---------"
        print "--------------------------------"
        #checks data offset for more than 5 words
        for i in tcp_header(data[0][34:54]).iteritems():                
            a, b = i
            print "{} : {} ".format(a,b)
         
    #Checks if UDP Protocol          
    elif temp_db[3] == 17:
        #UDP Header
        print "\n--------------------------------"
        print "----------- UDP HEADER ---------"
        print "--------------------------------" 

        for i in udp_header(data[0][34:42]).iteritems():
            a, b = i
            print "{} : {} ".format(a,b)
        
    #Checks if ICMP Protocol
    elif temp_db[3] == 1:
        #ICMP Header
        print "\n--------------------------------"
        print "---------- ICMP HEADER ---------"
        print "--------------------------------" 

        for i in icmp_header(data[0][34:38]).iteritems():
            a, b = i
            print "{} : {} ".format(a,b)
        
def check_int():
    #ask for user input and check if it's an integer
    user_input = raw_input("What would you like to do?\n")
    try:
        user_input = int(user_input)
    except ValueError:
        print ("Please input a valid response.")
        user_input = check_int()
    return user_input

#Menu for selecting which packets to enumerate
def packetChoice(data):
    #data is now a list of packets   
    runMenu = True

    while runMenu == True:
        print "\nEnumeration Station"
        print "1. Single packet"
        print "2. Range of Packets"
        print "3. Multiple Packets"
        print("4. Previous Menu")
        print("{:_^20}").format("")
        userInput = check_int()
        if (userInput == 1):
            pkChoice = onePacket()
            print "Packet {}".format(pkChoice)
            enumeratePacket(data[pkChoice])
        elif (userInput == 2):
            pkStart = rangeStart()
            packet_num = pkStart
            pkEnd = rangeEnd()
            for i in range(pkStart, pkEnd + 1):
                print "\nPacket  {}".format(packet_num)
                enumeratePacket(data[i])
                packet_num += 1
        elif (userInput == 3):
            enumeratePacket(data[i])
        elif (userInput == 4):
            break
        else:
            print("{:_^20}").format("")
            print("That was not a valid option.")
            print("{:_^20}").format("")

