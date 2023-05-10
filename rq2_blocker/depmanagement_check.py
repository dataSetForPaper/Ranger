import csv


def check_confirmed():
    with open('rq2_blocker/vul_dependencyManagement_result.csv') as f:
        visited = set()
        for l in csv.reader(f):
            cve, g,a,v,res = l
            if res=='confirmed':
                visited.add(g+'|'+a)
        print(len(visited))