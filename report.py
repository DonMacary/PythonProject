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

    while True:
        try:
            if line_num % 50 == 0:
                print "\n\n[+[ ----------------------- Macary Madness --------------------------[+]"
                print "{} | {} | {} | {} | {} | {} | {} |".format(" No.", 
                "Time", "Source IP", "Destination IP", "Protocol", "Length", "Information")
            else:
                dt = datetime.time()
                rp_data = []
                for i in ip_header(data[0][14:34]).iteritems():    
                    a, b = i
                    rp_data.append(line_num)
                    rp_data.append(dt)
                    rp_data.append(b)      
            print " {} | {} | {} | {} | {} | {} | {}".format(rp_data[0], 
                rp_data[1], rp_data[2], rp_data[11], 
                rp_data[5], rp_data[3], 
                rp_data[10])
            packet_db.append(rp_data)
            line_num += 1
        except KeyboardInterrupt:
            break