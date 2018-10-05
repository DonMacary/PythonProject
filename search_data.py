# search_data.py

"""
    This file will handle the search functions.
    The search functions should work on both a packet list in memory
    and a packet list from a file
"""
from datetime import datetime
from ipprotoconvert import *
import collections

"""
    Menu for search fields to be selected
"""
def printMenu():
    print("What would field would you like to search on?")
    print("(1). Packet Number")
    print("(2). Time")
    print("(3). Source IP")
    print("(4). Destination IP")
    print("(5). Protocol")
    print("(6). Packet Length")

"""
    Menu for the different types of conditions to be selected
"""
def printConditions():
    print("Which condition does the element need to have?")
    print("(1). Match (==)")
    print("(2). Like ('contains')")
    print("(3). Not (!=)")

"""
    Ask for the user input and validates that the input is correct
"""
def user_validation(choices):
    user_input = raw_input("::: ")
    try:
        user_input = int(user_input)
    except ValueError:
        print("Input is a not a valid int.  Please choose again.")
        user_input = user_validation(choices)
    if user_input < 1 or user_input > choices:
        print("Input was out of range. Please choose again.")
        user_input = user_validation(choices)
    return user_input

""" 
    Asks the user for the search parameters to be used on a provided packet list
"""
def build_search_statement():
    search_operations = []
    next_op = ""
    # Continue until user has input all conditions they desire to search on
    while True:
        search_element = []
        if next_op == "AND" or next_op == "OR":
            search_element.append(next_op)
        printMenu()
        try:
            field_choice = user_validation(6)
            search_element.insert(0, field_choice)
            field_value = raw_input("Value to be searched::: ")
            search_element.insert(1, field_value)
            printConditions()
            operations_choice = user_validation(3)
        except KeyboardInterrupt:
            break
        search_element.insert(2, operations_choice)
        search_operations.append(search_element)
        user_input = ""
        # Prompts user if any further conditions will be added
        while True:
            try:
                user_input = raw_input(
                        "Would you to add another search element(Y or N)?")
            except:
                break
            if user_input.upper() == 'Y' or user_input.upper() == 'N':
                break
            else:
                print("Input was not a valid choice.  Please choose again.")
        if user_input.upper() == 'N':
            break
        else:
            # If another condition will be added, then it will be either
            # ANDed or ORed with the previous element
            while True:
                try:
                    print("Will the next element be AND or OR to this element?")
                    user_input = raw_input("::: ")
                except KeyboardInterrupt:
                    break
                if user_input.upper() == "AND" or user_input.upper() == "OR":
                    next_op = user_input.upper()
                    break
                else:
                    print("Input was not a valid choice.  Please choose again.")
    return search_operations

"""
    The search operation is performed on the provided list
"""
def search_list(parsed_packet_db):
    filter_list = []
    field = 0
    value = 0
    cond = 0
    options = {1: "No.",
            2: "Time",
            3: "Source Address",
            4: "Destination Address",
            5: "Protocol",
            6: "Total Length"}

    # The search statement is built here
    search_op = build_search_statement()
    matches = False
    prev_match = False
    # Each packet from the list is looked at
    for item in parsed_packet_db:
        # Each search condition is compared against
        for search in search_op:
            field = search[0]
            value = search[1]
            cond = search[2]
            # Each element in the packet is compared against 
            # the search condition
            for key, dict_value in item.iteritems():
                # If the key matches one of field to be compared to
                if options[field] == key:
                    # If EQUALS is selected, search value must match 
                    # the packet value
                    if (cond == 1) and (value == str(dict_value)):
                        matches = True
                    # If LIKE is selected, search value must be contained
                    # in the packet value
                    if (cond == 2) and (value in str(dict_value)):
                        matches = True
                    # If NOT is selected, search value must not be 
                    # the packet value
                    if (cond == 3) and (value != str(dict_value)):
                        matches = True
            # If OR has been selected or the search condition is the first
            # in the statement, then prev_match will be False
            # only if both prev_match and matches are False
            if len(search) < 4 or search[3] == "OR":
                if matches is False and prev_match is False:
                    prev_match = False
                else:
                    prev_match = True
            else:
                # If AND was selected, then prev_match will be False
                # unless both are True
                if matches is False or prev_match is False:
                    prev_match = False
                else:
                    prev_match = True
        # If all the search conditions come to the conclusion of True
        # Then the packet can be added to the filter list
        if prev_match is True:
            filter_list.append(item)
        prev_match = False
        matches = False
    return filter_list

"""
    This function will search a provided file name and return a filtered list
"""
def search_file(filename):
    parsed_packet_db = []
    line_num = 1
    # The file is opened and stored into a list of ordered dictionaries
    with open(filename, "r") as file_read:
        for line in file_read:
            packet = collections.OrderedDict() 
            line_split = line.split(" ")
            packet["No."] = line_num
            packet["Time"] = datetime.strptime(line_split[1][0:8], 
                    "%H:%M:%S").strftime("%H:%M:%S")
            packet["Source Address"] = line_split[13]
            packet["Destination Address"] = line_split[14]
            packet["Protocol"] = line_split[11]
            packet["Total Length"] = line_split[7]
            if int(packet["Protocol"]) == 1:
                packet["Header Checksum"] = line_split[17]
            if int(packet["Protocol"]) == 6:
                packet["Header Checksum"] = line_split[15]
                packet["Header Checksum"] += " -> "
                packet["Header Checksum"] += line_split[16]
                flags = int(line_split[20])
                packet["Header Checksum"] = tcpFlags(flags)
            if int(packet["Protocol"]) == 17:
                packet["Header Checksum"] = line_split[15]
                packet["Header Checksum"] += " -> "
                packet["Header Checksum"] += line_split[16]
            parsed_packet_db.append(packet)
            line_num += 1
    # Here, the available packets from the file are printed
    print("Pulled From File: {}").format(filename)
    print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(" No.",
            "Time", "Source IP", "Destination IP", "Protocol", "Length", 
            "Information")
    for packet in parsed_packet_db:
        print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(
                packet["No."], packet["Time"], packet["Source Address"], 
                packet["Destination Address"], protoName(int(packet["Protocol"])), 
                packet["Total Length"], packet["Header Checksum"])
    # Here, the search operations are called on the built packet list
    output = search_list(parsed_packet_db)
    return output
"""
    The hook function from main that prompts the user if they are searching
    from the provided packet list or from a file
"""
def search_packets(parsed_packet_db):
    print("Would you like to search on packets in memory(1)"),
    print("or search on packets in a file(2)?")
    try:
        user_choice = user_validation(2)
    except KeyboardInterrupt:
        return
    filtered_list = []
    if user_choice == 1:
        if parsed_packet_db:
            filtered_list = search_list(parsed_packet_db)
        else:
            print("No packets in memory. Please use listening function first.")
    else:
        while True:
            try:
                print("What file would you pull packet from?")
                file_name = raw_input(":::")
            except KeyboardInterrupt:
                break
            try:
                file_test = open(file_name, 'rb')
                file_test.close()
            except IOError:
                print("Could not read from file name provided.")
                print("Would you like to try again?(Y or N)")
                while True:
                    try:
                        user_choice = raw_input(":::")
                    except KeyboardInterrupt:
                        break
                    if user_choice.upper() != 'Y' and user_choice.upper() != 'N':
                        print("Not a valid input. Please input again.")
                    else:
                        break
                if user_choice.upper() == 'N':
                    break
                if user_choice.upper() == 'Y':
                    continue
            filtered_list = search_file(file_name)
            break
    if parsed_packet_db:
        print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(" No.", 
                "Time", "Source IP", "Destination IP", "Protocol",
                "Length", "Information")
        for packet in filtered_list:
            print(" {:4} | {:8} | {:16} | {:16} | {:8} | {:6} | {:8} ").format(
                    packet["No."], packet["Time"], packet["Source Address"], 
                    packet["Destination Address"], protoName(int(packet["Protocol"])), 
                    packet["Total Length"], packet["Header Checksum"])
        print("")
