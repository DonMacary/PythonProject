# PythonProject
Authors: 

    Donald Macary - Project Manager/Developer
    Ricky Smith - Developer
    Robert Grahm - Developer
    Will Kraiser - Developer
    Zack Verring - Developer

# Packet Sniffer
Description: This tool will gather packets coming in on an interface and display them on a table. This tool will then export the results to a file which will allow the user to search through the results. 

**This tool WILL:**
* allow users to choose an interface for which to gather packets from.
* read all protocol types.
* display basic packet information on a table.
* allow user to search for specific packets from results.
* print all data to a file for further analysis.
* allow user to displlay more detailed information about specific packets. 

**This tool MAY:**
* incorporate a graphical user interface (GUI) to display information.
* allow user to filter packets that are displayed to the screen.
* allow user to filter packets on the exported results file. 

## Major Functions:

Main Menu():


Listen():

    This function will ask the user which interface they would like to listen on.
    It will then create a raw socket accepting all protocol types on that interface. 
    It will also create and print a display table heading. 
    The main function will call the report function.

Report():

    This function will display the following information for each packet:
        Sequence Number (What order the packet was read by the sniffer)
        Time (To the milisecond?)
        Source IP
        Destination IP
        Protocol
        Length (in Bytes)
        Packet Information (Source and Dest Port, Flags, Data)
    Additionally, all of the packets will be exported to a file for future enumeration. 

EnumeratePacket():

    This function will ask the user which packets they would like to enumerate (by packet no.)
    It will allow them to enumerate by: 
        Single packet EG: No. 5
        Range of packets EG: No. 5-10
        Several non-sequential packets EG: 5,8,2,13-16 
    Then the function will print out all the information for the packets specified. 
    NOTE: This function will enumerate from the list that is running in memory. IF the user wants to 
    print from an archive file they will need to enumerate from file.

EnumerateFromFile():

    This function will mirror the functionality of EnumeratePacket but will pull the data from a log file.

Search():

    This function will search the results file for specific packets based off the search conditions. 


## Projected timeline
28 September:
    
    Agree on project requirements, Create/Finish outline talk through design. 
    Create GIT project. Seek instructor approval for project. 

1 October:

    Create main method and the base functionality of report. 
    As a full team get packets to come in so that we can split into 
    small teams to work on further advances. 

2 October:

    Split into teams:
    Team 1 - Work on Export and import functionality
    Team 2 - Work on search functionality
    Team 3 - Work on Enumerate functionality

5 October:

    Reconvene as a group and implement all functionality. 
    Fix bugs incorporated with joining different code.
    (EEK) 4 hours enough time? 
    Present results to instructors. 


## Daily Log
1 October:

    Sniffer is able to grab all packets and print them, created classes for each packet type.
    Split into teams to create functionality:
        Team 1: Kraiser and Smith -> Formatting output into table.
        Team 2: Grahm -> Export Functionality
        Team 3: Verring -> creating main menu (DONE)
        Team 4: Macary -> Print available interfaces to listen on. 
                -> found psutil library to help with this Verring now helping to add this to listen
            
    




## SET UP INSTRUCTIONS

    The programm requires the psutil library. To install follow the instructions at
    https://github.com/giampaolo/psutil/blob/master/INSTALL.rst

    For the lazy:
        Windows -> pip install psutil
        fedora -> sudo yum install gcc python-devel python-pip
                  pip install psutil 


    