import string
import sys
import json

sys.stdout = open("labelingend"+ ".txt","w", -1, 'utf-8')

args1 = sys.argv[1]#original
args2 = sys.argv[2]#sus


f2 = open(args2) 
lines2 = f2.readlines()
lines2 = list(map(lambda s: s.strip(), lines2))

with open(args1) as f1:
    lines1 = f1.readlines()
    lines1 = list(map(lambda s: s.strip(), lines1))
    for line1 in lines1:            
        if line1 in lines2:
            print("1") 
        else :
            print("0") 

f1.close()
f2.close()