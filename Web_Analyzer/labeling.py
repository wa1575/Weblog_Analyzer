import string
import sys
import json



sys.stdout = open("suslabel"+ ".txt","w", -1, 'utf-8')

#나중에 병합하면 변경하기
#from parsing import args
args = sys.argv[1]

i = 1
sus = []
susresult = {}

with open('label.json', encoding="utf-8") as label_file:
    data = json.load(label_file)


label = [ x for x in data.values()]

label_result = []
for j in label:
    label_result.extend(j) 
#우선 label.json에 있다면 의심군으로 로그 가져오기 

label_result = [int (i) for i in label_result]


with open(args) as f:
    lines = f.readlines()
    lines = list(map(lambda s: s.strip(), lines))
    for line in lines:
        if i in label_result:
            print(line)
            #sus.append(line)
        i += 1 




#susresult.setdefault('sus', []).extend(sus)
"""
with open('result.json', 'w',encoding="utf-8") as fp:
    json.dump(susresult, fp, ensure_ascii=False, indent="\t")
    """
