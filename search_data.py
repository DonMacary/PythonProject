# search_data.py

"""
    This file will handle the search functions on the current packet list
"""

def printMenu():
    print("What would field would you like to search on?")
    print("(1). Packet Number")
    print("(2). Time")
    print("(3). Source IP")
    print("(4). Destination IP")
    print("(5). Protocol")
    print("(6). Packet Length")

def printConditions():
    print("Which condition does the element need to have?")
    print("(1). Match (==)")
    print("(2). Like ('contains')")
    print("(3). Not (!=)")

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

def build_search_statement():
    search_operations = []
    next_op = ""
    while True:
        search_element = []
        if next_op == "AND" or next_op == "OR":
            search_element.append(next_op)
        printMenu()
        field_choice = user_validation(6)
        search_element.insert(0, field_choice)
        field_value = raw_input("Value to be searched::: ")
        print(field_value)
        search_element.insert(1, field_value)
        printConditions()
        operations_choice = user_validation(3)
        search_element.insert(2, operations_choice)
        search_operations.append(search_element)
        user_input = ""
        while True:
            user_input = raw_input(
                    "Would you to add another search element(Y or N)?")
            if user_input.upper() == 'Y' or user_input.upper() == 'N':
                break
            else:
                print("Input was not a valid choice.  Please choose again.")
        if user_input.upper() == 'N':
            break
        else:
            while True:
                print("Will the next element be AND or OR to this element?")
                user_input = raw_input("::: ")
                if user_input.upper() == "AND" or user_input.upper() == "OR":
                    next_op = user_input.upper()
                    break
                else:
                    print("Input was not a valid choice.  Please choose again.")
    return search_operations

def search_list(packet_db):
    filter_list = []
    filter_list2 = []
    field = 0
    value = 0
    cond = 0
    options = {1: "No.",
            2: "Time",
            3: "Source IP",
            4: "Destination IP",
            5: "Protocol",
            6: "Length"}

    search_op = build_search_statement()
    matches = False
    prev_match = False
    for item in packet_db:
        for search in search_op:
            field = search[0]
            value = search[1]
            cond = search[2]
            for key, dict_value in item.iteritems():
                if options[field] == key:
                    if value == str(dict_value):
                        matches = True
                if ((cond == 1 and options[field] == key 
                    and dict_value == value)
                    or (cond == 2 and options[field] == key 
                        and value in dict_value) 
                        or (cond == 3 and options[field] == key and 
                            dict_value != value)):
                    matches = True
            if len(search) < 4 or search[3] == "OR":
                if matches is False and prev_match is False:
                    prev_match = False
                else:
                    prev_match = True
            else:
                if matches is False or prev_match is False:
                    prev_match = False
                else:
                    prev_match = True
        if prev_match is True:
            filter_list.append(item)
        prev_match = False
        matches = False
    return filter_list

# Test Section to see if filter search works on a provide data set

# test_list = []
# test_element = {"Packet Number": 1, "Time": "test","Source IP":"192.168.31.128","Destination IP":"192.168.31.31","Protocol":6,"Packet Length":17}
# test_list.append(test_element)
# test_element = {"Packet Number": 2, "Time": "test","Source IP":"192.168.31.129","Destination IP":"192.168.31.29","Protocol":6,"Packet Length":23}
# test_list.append(test_element)
# test_element = {"Packet Number": 3, "Time": "test","Source IP":"192.168.31.130","Destination IP":"192.168.31.31","Protocol":7,"Packet Length":17}
# test_list.append(test_element)
# test_element = {"Packet Number": 4, "Time": "test","Source IP":"192.168.31.131","Destination IP":"192.168.31.31","Protocol":6,"Packet Length":17}
# test_list.append(test_element)
# test_element = {"Packet Number": 5, "Time": "test","Source IP":"192.168.31.132","Destination IP":"192.168.31.28","Protocol":9,"Packet Length":17}
# test_list.append(test_element)
# output = []
# output = search_list(test_list)
# print(output)
