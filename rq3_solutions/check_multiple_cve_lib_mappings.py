import json
from collections import defaultdict

ret = defaultdict(set)
for cve, libvers in json.load(open('vul_edges.json')).items():
    for libver in libvers:
        v = libver.split(':')[-1]
        ga = libver.replace(':'+v, '')
        ret[cve].add(ga)

count = 0
for cve, libver in ret.items():
    if len(libver)>3:
        print(cve)
        count+=1
print(count)
