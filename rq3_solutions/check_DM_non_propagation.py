# on graph instance
import csv
import json
import os
import concurrent
import pandas as pd

from check_dependencyManagement import get_dependencyManagements
m2 = ''
vulf = open('vul_edges.json')
vul_edges = json.load(vulf)

vul_edges_set = {}
for cve, gavs in vul_edges.items():
    vul_edges_set[cve] = set(gavs)
def get_visited():
    visited = set()
    with open('') as f:
        for l in csv.reader(f):
            visited.add(l[0])
    return visited

# on graph instance
def check_DM_non_propagation():
    visited = get_visited()
    for cve in os.listdir('by_cve'):
        if 'SEC' in cve or 'CNVD' in cve or 'CNNVD' in cve:
            continue
        print(cve)
        if cve in visited:
            continue

def check_how_many_cve_DM_avoid(deps, vul_edges):

    no_dm = False
    no_cve = False
    avoid = False
    affect = False
    if len(deps) ==0:
        no_dm = True
        return no_dm, no_cve, avoid, affect
    for dep in deps:
        g,a,v = dep
        for cve, dep_gavs in vul_edges.items():
            if affect and avoid:
                break
            if g+':'+a+':'+v in dep_gavs:
                affect = True
            else:
                for dep_gav in dep_gavs:
                    if g+':'+a in dep_gav:
                        avoid = True
                        break
    if not affect and not avoid:
        no_cve = True

    return no_dm, no_cve, avoid, affect


def process_one_gav(gav):
    vendor, library, version = gav.split('|')
    print(vendor, library, version, '\r', end='', flush=True)
    pom_path = m2 + vendor.replace('.', '/') + '/' + library + '/' + version + '/' + library + '-' + version + '.pom'
    try:
        deps = get_dependencyManagements(pom_path)
    except Exception as e:
        print(e)
        return
    no_dm, no_cve, avoid, affect = check_how_many_cve_DM_avoid(deps, vul_edges_set)
    with open('dm_usage.csv', 'a') as output:
        csv.writer(output).writerow([vendor, library, version, no_dm, no_cve, avoid, affect])

def get_DM_usage():
    names = []
    with open('maven_ga_sv.json') as f:    
        gav = json.load(f)
        for ga, sv in gav.items():
            for version in sv:
                names.append(ga+'|'+version)
    with concurrent.futures.ProcessPoolExecutor(25) as executor:
        executor.map(process_one_gav, names)

def parse_dm_usage():
    with open('dm_usage.csv') as f:
        no_dm_count = 0
        no_cve_count = 0
        affected = 0
        avoid =0
        overlap = 0

        for l in csv.reader(f):
            if l[3] == 'True':
                no_dm_count+=1
            if l[4] =='True':
                no_cve_count+=1
            if l[5] == 'True':
                avoid +=1
            if l[6] == 'True':
                affected +=1
            if l[5] == 'True' and l[6] == 'True':
                overlap += 1
        print(no_cve_count, no_dm_count, affected, avoid, overlap)
if __name__ == '__main__':
    get_DM_usage()
    parse_dm_usage()
