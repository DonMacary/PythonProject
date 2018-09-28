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

Main():

    This function will create a raw socekt accepting all protocol types. It will bind that socket to an interface of the users choosing. It will also create and print a display table heading. The main function will call the report function.

Report():

    This function will display the following information for each packet:
        Sequence Number (What order the packet was read by the sniffer)
        Time (To the milisecond?)
        Source IP
        Destination IP
        Protocol
        Length (in Bytes)
        Packet Information
    Additionally, all of the packets will be exported to a file for future enumeration. 

Enumerate Packet():

    This function will enumerate more details about specific packets. It will look further into the protocol specific information.

Search():

    This function will search the results file for specific packets based off the search conditions. 


## Projected timeline
28 September:
    
    Agree on project requirements, Create/Finish outline talk through design. Create GIT project. Seek instructor approval for project. 

1 October:

    Create main method and the base functionality of report. As a full team get packets to come in so that we can split into small teams to work on further advances. 

2 October:

    Split into teams:
    Team 1 - Work on Export and import functionality
    Team 2 - Work on search functionality
    Team 3 - Work on Enumerate functionality

5 October:

    Reconvene as a group and implement all functionality. Fix bugs incorporated with joining different code. (EEK) 4 hours enough time? 
    Present results to instructors. 
