import csv
import json
import os

import requests



def drop_duplicates(file):
    with open(file, 'r') as in_file, open(file.replace('.csv', '_unique.csv'), 'w') as out_file:
        seen = set()  # set for fast O(1) amortized lookup
        for line in csv.reader(in_file):
            if line[1] in seen:
                continue  # skip duplicate

            seen.add(line[1])
            csv.writer(out_file).writerow([line[1]])

def count_lib_only(file):
    with open(file) as f:
        gas = set()
        for l in csv.reader(f):
            if l[0]=='cve':
                continue
            g,a,v = l[1].split(('|'))
            gas.add(g+'|'+a)
        print(file, ':', len(gas))
    with open(file.replace('.csv', '_lib.csv'), 'w') as fw:
        writer = csv.writer(fw)
        for each in gas:
            writer.writerow([each.replace('|', ':')])

def other_dep_analysis():
    count_lib_only('rq2_blocker/other_dep_after_patch_unique.csv')
    count_lib_only('rq2_blocker/other_dep_before_patch_unique.csv')
    count_lib_only('rq2_blocker/other_dep_non_patch_unique.csv')

    visited = set()
    with open('rq2_blocker/other_dep_after_patch.csv', 'r') as f, open('rq2_blocker/other_dep_before_patch.csv',
                                                                       'r') as f2, open(
            'rq2_blocker/other_dep_non_patch.csv', 'r') as f3:
        for l in csv.reader(f):
            visited.add(l[0])
        for l in csv.reader(f2):
            visited.add(l[0])
        for l in csv.reader(f3):
            visited.add(l[0])
    with open('rq2_blocker/other_dep_after_patch.csv', 'a') as f, open('rq2_blocker/other_dep_before_patch.csv', 'a') as f2, open('rq2_blocker/other_dep_non_patch.csv', 'a') as f3:
        writer = csv.writer(f)
        writer2 = csv.writer(f2)
        writer3 = csv.writer(f3)
        cve_patch_dates = json.load(open('rq2_blocker/cve_patch_date.json'))
        lagged_deps = []
        non_lagged_deps = []
        for cve in os.listdir('by_cve'):
            print(cve)
            if cve in visited:
                continue
            if os.path.exists('by_cve/'+cve+'/response.json'):
                deps = json.load(open('by_cve/'+cve+'/response.json'))
                if 'status' in deps:
                    continue
                if os.path.exists('by_cve/'+cve+'/response_patch.json'):
                    patched_deps = json.load(open('by_cve/'+cve+'/response_patch.json'))
                    reorganized = {}
                    for each in patched_deps:
                        g = each['vendor']
                        a = each['library']
                        v = each['version']
                        if g+'|'+a in reorganized:
                            if reorganized[g + '|' + a]['date']>each['proList'][1]['propertyContent']:
                                reorganized[g + '|' + a] = {'lvl': each['proList'][1]['propertyContent'],
                                                            'date': each['proList'][0]['propertyContent'], 'version': v}
                        else:
                            reorganized[g+'|'+a] = {'lvl': each['proList'][1]['propertyContent'], 'date': each['proList'][0]['propertyContent'], 'version': v}
                    for dep in deps:
                        if dep['proList'][1]['propertyContent']!='1':
                            vul_date = dep['proList'][0]['propertyContent']
                            lvl = dep['proList'][1]['propertyContent']
                            g = dep['vendor']
                            a = dep['library']
                            v = dep['version']
                            if g+'|'+a in reorganized:
                                patched_date = reorganized[g+'|'+a]['date']
                                downstream_deps = get_downstream_deps(g, a, v, lvl)
                                for down_dep in downstream_deps:
                                    release_date = down_dep['proList'][0]['propertyContent']
                                    dg = down_dep['vendor']
                                    da = down_dep['library']
                                    dv = down_dep['version']
                                    if release_date >= patched_date:

                                        writer.writerow([cve, dg+'|'+da+'|'+dv, release_date, patched_date])
                                    else:
                                        writer2.writerow([cve, dg+'|'+da+'|'+dv, release_date, patched_date])
                            else:
                                writer3.writerow([cve, g+'|'+a+'|'+v, vul_date])

