#This function will display the table while listening

#This import is necessary to call report()
import report as rp
import datetime

#This line needs to be inserted into main loop to print the table
rp.report(pkt)

#Global variables
line_num = 0
packet_db = []

def report(data):
    global packet_db

    try:
        if line_num % 50 == 0:
            print "\n\n[+[ ----------------------- Macary Madness --------------------------[+]"
            print "{} | {} | {} | {} | {} | {} | {} |".format(" No.",
                    "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
        else:
            dt = datetime.time()
            rp_data = {}
            for i in ip_header(data[0][14:34]).iteritems():
                a, b = i
                rp_data[a] = b
            rp_data["Time"] = dt
            rp_data["No."] = line_num
        print " {} | {} | {} | {} | {} | {} | {}".format(rp_data["No."], 
                rp_data["Time"], rp_data["Source Address"], rp_data["Destination Address"], 
                rp_data["Protocol"], rp_data["Total Length"], rp_data["Header Checksum"])
        packet_db.append(rp_data)
        line_num += 1
    except KeyboardInterrupt:
