import csv
import os
import json

import dateutil

from rq2_blocker.other_deps_analysis import drop_duplicates
def count_lib_only(file):
    with open(file) as f:
        gas = set()
        for l in csv.reader(f):
            if l[0]=='lagged_gav':
                continue
            g,a,v = l[0].split(('|'))
            gas.add(g+'|'+a)
        print(file, ':', len(gas))
    with open(file.replace('.csv', '_lib.csv'), 'w') as fw:
        writer = csv.writer(fw)
        for each in gas:
            writer.writerow([each.replace('|', ':')])


def analyze_lagged_first_dep():
    count_lib_only('rq2_blocker/first_dep_after_patch_unique.csv')
    count_lib_only('rq2_blocker/first_dep_before_patch_unique.csv')
    # drop_duplicates('rq2_blocker/first_dep_after_patch.csv')
    # drop_duplicates('rq2_blocker/first_dep_before_patch.csv')
    exit()
    with open('rq2_blocker/first_dep_after_patch.csv', 'w') as f, open('rq2_blocker/first_dep_before_patch.csv', 'w') as f2:
        writer = csv.writer(f)
        writer2 = csv.writer(f2)
        writer.writerow(['cve', 'lagged_gav'])
        writer2.writerow(['cve', 'lagged_gav'])
        cve_patch_dates = json.load(open('rq2_blocker/cve_patch_date.json'))
        lagged_deps = []
        non_lagged_deps = []
        for cve in os.listdir('by_cve'):
            # if cve != 'CVE-2021-44228':
            #     continue
            if 'SEC' in cve or 'CNVD' in cve or 'CNNVD' in cve:
                continue
            patch_date = cve_patch_dates.get(cve, '')
            if patch_date == '':
                print(cve)
                continue

            if os.path.exists('by_cve/'+cve+'/response.json'):
                deps = json.load(open('by_cve/'+cve+'/response.json'))
                if 'status' in deps:
                    continue

                for dep in deps:
                    if dep['proList'][1]['propertyContent']=='1':
                        date = dep['proList'][0]['propertyContent']
                        stamp = dateutil.parser.isoparse(date)
                        # print(cve)
                        patch_stamp = dateutil.parser.isoparse(patch_date)
                        if stamp>=patch_stamp:
                            g = dep['vendor']
                            a = dep['library']
                            v = dep['version']
                            lagged_deps.append(g+'|'+a+'|'+v)
                            writer.writerow([cve, g+'|'+a+'|'+v])
                        else:
                            g = dep['vendor']
                            a = dep['library']
                            v = dep['version']
                            non_lagged_deps.append(g + '|' + a + '|' + v)
                            writer2.writerow([cve, g + '|' + a + '|' + v])




