#!/usr/bin/env python
from scapy.all import *

import sys



rf = open( sys.argv[1], 'r')
line_num = rf.read().count("\n")
rf.close()

rf = open( sys.argv[1], 'r')
rf2 = open( sys.argv[2], 'r')
wf = open( os.path.splitext(sys.argv[1])[0]+"_or.txt", 'w' )




cnt = 0
buffer = ""



def or_func():

    global buffer,cnt
    while line_num-cnt >0:
        first = rf.readline()
        second = rf2.readline()
        print("%dth %s or %s" % (cnt, first[:-1], second[:-1]))
        if first == "1\n" or second == "1\n":
            buffer += "1\n"
        else:
            buffer += "0\n"
        cnt+=1

    wf.write(buffer)
    wf.close()
    rf.close()
    rf2.close()



if __name__ == '__main__':
    or_func()


