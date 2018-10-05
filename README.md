# PythonProject
Authors: 

    1Lt Donald Macary - Project Manager
    2dLt Ricky Smith - Developer
    SSgt Robert Grahm - Developer
    SSgt Will Kraiser - Developer
    SSgt Zack Verring - Developer

## Project Description:
* In a group, create a python program.
* This program must be completed by Friday October 5 (5 days).
	
## Group Requirements:
* Build a program that utilizes networking/sockets.
* Build a program that can be completed in a short timeline.
* Utilize good error checking/documentation, adheres to pep8.

# Packet Sniffer

**Description:** This tool is a command line tool written in python that allows a user to display and analyse packet data on any/all interfaces on their system. Currently this tool is compatible with LINUX operating systems and runs through python 2.7. Users will need to follow the setup and run instructions in order to run the program.


## Project Requirements
**This tool WILL:**
* allow users to choose an interface to gather packets from.
* read all protocol types.
* display basic packet information on a table.
* allow user to search for specific packets from results.
* print all data to a file for further analysis.
* allow user to display more detailed information about specific packets. 
* adhere to pep8 standards.
* be written in Python 2.7.

**This tool MAY:**
* incorporate a graphical user interface (GUI) to display information.
* allow user to filter packets that are displayed to the screen.
* allow user to filter packets on the exported results file. 
* be portable for all OS versions. 


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

4 October:

    Reconvene as a group and implement all functionality. 
    Fix bugs incorporated with joining different code.
    (EEK) 4 hours enough time? 


5 October:

    Present program to instructors. 
    Fix any issues. 
    Present 


## Files:

### **__main__.py**
* Central executable for program - this file is called to start program. 
* Displays the main menu and makes calls to different functions based on user input.
* Asks the user if they would like to:
    * Listen 
    * Search
    * Enumerate
    * Print from File
    * Quit
* Calls the functions to accomplish each task.
* The menu loops until the user chooses to quit the program or an error occurs. 

### **report.py**
* Provides the main functionality for displaying the packets table. 
* Prints the table's column titles every 50 packets/lines.  
* Takes in an unpacked packet, unpacks it and displays the information in a formatted table.
* Appends a line number and timestamp to all packets.
* Adds unpacked packet to a database for use in other functions in the program.

### **print_table.py**
* Prompts the user to provide a path to a log file
* Reads the file the user provides and parses the data into a list.  
* Further breaks down data into smaller lists in order to format and display correct data
* After the function completes displaying all the fields in the log file, it closes the file.

 ### **search_data.py**
* Executes the search option on either a provided list of packets or a prompted filename.  
* User will then be prompted for search conditions (Fields will be picked, values will be selected, either MATCH, CONTAINS, or NOT will be selected, and lastly, any new conditions will be either ANDed or ORed).  
* A filtered list of packets will be provided back and displayed.  The function will execute once when called, but can be called as many times as desired by the user.
* Function that main will call to hook into this set of functions is search_packets(parsed_packet_db). Parsed_packet_db is the list of packets that was gathered from the listener

### **Shared_Headers.py**
* Contains classes for all common header types. This is called in many functions 

### **listener.py**
* Prompts the user to choose an interface to begin listening for packets on.
* Creates a RAW socket bound to the user-specified interface
    * Note this is one of the two major reasons why this program is not portable. 
* Creates a log file to store packet data
* Listens for packets coming into the interface and passes that information into three functions.
    * First it adds the raw packet to a database in memory
    * Second it writes the packet to the log file on disk
    * Third it passes the packet into the display table function to display some packet information to the user
* Continues running until user hits Ctrl+C then breaks back to main menu

### **ipprotoconvert.py**
* Provides a dictionary of all protocol types and their integer value.
* Provides the protoname function to convert protocol ints to protocol keyword strings.
* Other similar functions do not display the information we wanted in this program. 
## Daily Log
1 October:

    Sniffer is able to grab all packets and print them, created classes for each packet type.
    Split into teams to create functionality:
        Team 1: Formatting output into table.
        Team 2: Export Functionality
        Team 3: creating main menu (DONE)
        Team 4: Print available interfaces to listen on. 
                -> found psutil library to help with this Verring now helping to add this to listen
            
2 October:

    Finished function to print all information to a file. Began search functionality (Grahm). 
    Completed listening function - allows users to select interface.
    Completed report function so a table of packet information is printed.
    Added a dictionary file with all protocol keywords so the table will print keywords vs numbers.
    Started enumerate functionality (Kraiser/Smith)
    Started Print From File functionality (Verring)
    Switching packet database from list of list to list of dictionaries (Grahm)

4 October:

    Began compiling all features into main program
    Finished compiling all features into main program
    Began testing all features - started tracking bugs and fixing them. 
    Started cleaning up code and adding last minute features
    Info column being worked on to display more information (such as SP DP flags etc...)



## SET UP AND RUN INSTRUCTIONS

    The programm requires the psutil library. To install follow the instructions at
    https://github.com/giampaolo/psutil/blob/master/INSTALL.rst

    For the lazy:
        Windows -> pip install psutil
        fedora -> sudo yum install gcc python-devel python-pip
                  sudo pip install psutil 
    To run the program type:
        sudo python2 __main__.py 

## Project Problems:
**Requirements**
* Very few requirements made it difficult to define project parameters

**Timeline**
* Short timeline limited ability to create advanced features
* Rushed planning component of program forcing team to make many design features "on the fly"
* Error checking and documentation quality suffered

**Inexperienced Project Management**
* PM not a trained project manager. 
* Did not have an organized project management program. (used a whiteboard to track team progress)
* Many errors managing github branches (erasing progress when merging into master).
* Many features were not defined well when tasking developers.
    * Caused errors when incorporating different functions back into major program
* Stopped tracking major accomplishments/ problems by day after day 2 

**Error Checking**
* Some error checking incorporated but many flaws are indoubtedly in program still.
* Most functions were not created with error checking in mind. 
* Many functions do not gracefully encounter errors -> meaning if an error occurs the program will crash.

## Things that worked well
**Teamwork**
* Team worked well at dividng responsibility so that everyone always had a task to complete. 
    * Very little wasted time
    * All features were completed
* Developers often helped other developers solve issues. 
* Quickly and easily solved issues when conflicts in the code came up.
* Slack improved communication - easily shared material and information among team. 

**Git Management**
* Team was able to combine code efficiently without stepping on each others toes.
* When mistakes were made it was easy to retrieve lost code.
* Everyone was able to work concurrently on different features. 

**Bug Fixing**
* Spent final day testing, fixing and improving code
* Used whiteboard to track program problems and bug fixes
* Developers reviewed other developer's code to try and optimise code

**Communication**
* All team members understood responsibilities. 
* Developers understood what their part of the program should do.
* Developers given freedom to create functionality however they wanted. 

**Time Management**
* Team stuck to projected timeline through process.
* Stayed on task throughout class time. 
* All core functionality completed on time with bug fixing.



