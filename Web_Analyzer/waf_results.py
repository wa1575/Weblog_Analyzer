#!/usr/bin/env python
from scapy.all import *
import scapy.layers.http  as http# import HTTP packet

import sys

src_ip = sys.argv[1]

rf = open( sys.argv[2], 'r' )
wf = open( os.path.splitext(sys.argv[2])[0]+"_label.txt", 'w' )
wf_verbose = open( os.path.splitext(sys.argv[2])[0]+"_rule_matched.txt", 'w' )


line_num = rf.read().count("\n")
rf.close()

cnt = 0
buffer = ""
buffer_verbose = ""
def showPacket(packet):


            if  packet.haslayer(http.HTTPRequest):
                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                # then show raw
                raw = (f"{packet[http.HTTPRequest]}")
                result = raw[raw.find("result")+7:raw.find("HTTP/1.1\\r\\nHost:")]

                accesslog = raw[raw.find("User-agent: ") + 12:-4]



                res = accesslog.split(' ')
                global cnt, buffer,buffer_verbose

                if int(res[0]) < cnt:
                    return
                print(accesslog[:-5])
                print(result)


                while int(res[0]) != cnt:
                    buffer+="0\n"
                    #print("0\n")
                    buffer_verbose+="0\n"
                    cnt += 1

                buffer += "1\n"
                #print("1\n")

                pattern = result[result.find(" [msg "):].split(']')[0]+"]"
                buffer_verbose +="1 "+pattern+"\n"




                if  cnt == line_num:
                    wf.write(buffer)
                    wf_verbose.write(buffer_verbose)
                    wf.close()
                    wf_verbose.close()
                    return

                cnt+=1






def sniffing(filter):
    sniff(filter=filter, prn=showPacket, store=False, timeout =5)
    global buffer,cnt,buffer_verbose
    while line_num-cnt >0:
        buffer_verbose += "0\n"
        buffer += "0\n"
        cnt+=1
    buffer_verbose += "0\n"
    buffer += "0\n"
    wf.write(buffer)
    wf_verbose.write(buffer_verbose)
    wf.close()
    wf_verbose.close()



if __name__ == '__main__':
    filter="ip "+src_ip+" and port 80"
    sniffing(filter)



