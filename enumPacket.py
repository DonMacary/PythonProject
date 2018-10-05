#Function will take in a packet and print the data
from shared_headers import *
import time

#Allows for combination of single packet and range of packet selection
def packetCombo():
    print "\nReady for packet selection"
    print "Separate packet number by comma (1,2) and range by dashes (4-6)"
    user_input = raw_input("Enter packet number and/or packet number range: ").rstrip()
    try:
        packRange = user_input.split(",")
        j = []
        for i in range(len(packRange)):
            try:
                packRange[i] = int(packRange[i])
                j.append(packRange[i])
            except:                
                temp = packRange[i].split("-")
                for num in range(int(temp[0]), (int(temp[1])+1), 1):
                    j.append(num)                
    except ValueError:
        print ("Please input a valid response.")
        user_input = packetCombo()
    return j

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
    if temp_db[6] == 6:    
        #TCP Header
        print "\n--------------------------------"
        print "----------- TCP HEADER ---------"
        print "--------------------------------"
        #checks data offset for more than 5 words
        for i in tcp_header(data[0][34:54]).iteritems():                
            a, b = i
            print "{} : {} ".format(a,b)         
    #Checks if UDP Protocol          
    elif temp_db[6] == 17:
        #UDP Header
        print "\n--------------------------------"
        print "----------- UDP HEADER ---------"
        print "--------------------------------" 

        for i in udp_header(data[0][34:42]).iteritems():
            a, b = i
            print "{} : {} ".format(a,b)        
    #Checks if ICMP Protocol
    elif temp_db[6] == 1:
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
        print "1. Choose packets"
        print("2. Previous Menu")
        print("{:_^20}").format("")
        userInput = check_int()
        if (userInput == 1):
            #Allows for single and packet range selection
            pkCombo = packetCombo()
            if pkCombo < 1:
                print "\nPacket Selection out-of-range"
                packetChoice(data)
                break
            else:                
                for i in pkCombo:                    
                    print "\nPacket {}".format(i)
                    enumeratePacket(data[i -1])
                    time.sleep(1)
        elif (userInput == 2):
            break
        else:
            print("{:_^20}").format("")
            print("That was not a valid option.")
            print("{:_^20}").format("")