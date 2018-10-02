#!/usr/bin/python
#
# Simplest Form Of Packet sniffer in python
# Works On Linux Platform 
 

#import report as rp
from shared_headers import *
from report import *

def buildFileName():
    file_choice = ''
    while True:
        print("Would you like to write to a new log file(N)"),
        user_input = raw_input("or the last one(L)?:::")
        if user_input.upper() != 'N' and user_input.upper() != 'L':
            print("User input is not valid.  Please choose again.")
        else:
            file_choice = user_input
            break
    full_file_name = ""
    packet_version = 1
    if file_choice == 'N':
        file_name = str(datetime.datetime.today().year) + "_"
        file_name += str(datetime.datetime.today().month) + "_"
        file_name += str(datetime.datetime.today().day)
        file_ext =  "_packet.log"
        list_of_files = os.listdir(os.getcwd())
        full_file_name = file_name + file_ext
        while full_file_name in list_of_files:
            full_file_name = file_name + "_(" + str(packet_version) + ")"
            full_file_name += file_ext
            packet_version += 1
        file_write = open(full_file_name, "w+")
        file_write.close()
    if file_choice == 'L':
        year = 0
        month = 0
        day = 0
        version = 0
        list_of_files = os.listdir(os.getcwd())
        for item in list_of_files:
            parts = item.split(".")
            if parts[len(parts) - 1] == 'log':
                if int(item.split("_")[0]) > year:
                    year = int(item.split("_")[0])
                if int(item.split("_")[0]) == year:
                    if int(item.split("_")[1]) > month:
                        month = int(item.split("_")[1])
                    if int(item.split("_")[1]) == month:
                        if int(item.split("_")[2]) > day:
                            day = int(item.split("_")[2])
                        if int(item.split("_")[2]) == day:
                            if "packet" not in item.split("_")[3]:
                                version = item.split("_")[3]
        full_file_name = str(year) + "_" + str(month) + "_" + str(day) + "_" + version
        full_file_name += "_packet.log"
    return full_file_name


def writeToLog(data):
    # file_log = open("packets.log", "a")
    current_date = str(datetime.datetime.now())
    # file_log.write(current_date) 
    # file_log.write(" ----------")

    print "\n\n[+] ------------ Ethernet Header----- [+]"
    for header in sh.eth_header(data[0][0:14]).iteritems():
        a, b = header
        print("{} :{} |").format(a, b)
    print "\n\n[+] ------------ IP Header ------------[+]"
    for i in sh.ip_header(pkt[0][14:34]).iteritems():
        a, b = i
        print "{} : {} | ".format(a, b)


#create an INET, raw socket
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

logfile = buildFileName()
# receive a packet
while True:
    try:
        # print output on terminal
        pkt = s.recvfrom(65565)
        #writeToLog(pkt)
        display_table(pkt)
    except KeyboardInterrupt:
        break

# if __name__ == "listener.py":
#     main()
        
