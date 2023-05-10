import csv
import json
import os
from collections import defaultdict
from datetime import datetime

import dateutil
import pymongo
import requests

from config import mongodb_host, mongodb_port, graph_api_host
from soft_version_query import get_all_vuls


def patch_date_analysis():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    maven = c['library-crawler']['maven']
    modified_date = '2022-12-01'
    if not os.path.exists('cves.json'):
        cves = get_all_vuls()
        with open('cves.json', 'w') as f:
            f.write(json.dumps(cves))
    else:
        cves = json.load(open('cves.json'))

    print('To be processed cves:', len(cves))
    os.makedirs('by_cve', exist_ok=True)
    advisory = json.load(open('gitcve2gav.json'))
    with open('rq2_blocker/vul_lib_patch_date_diff.csv', 'w') as f:
        writer =csv.writer(f)
        writer.writerow(['cve', 'diff', 'patch_date', 'cve_date'])
        for i, cve in enumerate(cves):

            doc = cve_created_time.find_one({'cve': cve})
            if not doc:
                continue
            if 'SEC' in cve or 'CNVD' in cve or 'CNNVD' in cve:
                continue
            fix_dates = []
            created_date = dateutil.parser.isoparse(doc['time'].replace('.', '-'))
            if cve in advisory:
                fix_libs = advisory[cve]
                fix_date = None

                for fix_lib in fix_libs:
                    g, a = fix_lib['ga'].split(':')
                    version_range = fix_lib['version_range']
                    fix_version = version_range.split(', ')[-1].replace(']', '')
                    if fix_version!=' ':
                        fix_doc = maven.find_one({'group': g, 'artifact': a, 'version': fix_version})
                        if fix_doc:
                            fix_date = datetime.fromtimestamp(int(fix_doc['time'])/1000)
                            fix_dates.append(fix_date)

                    else:
                        writer.writerow([cve, None, None, created_date])

                fix_dates.sort()
            else:
                response = requests.post(f'http://{graph_api_host}:8090/getPatchDate', json={"vulnerabilityId": cve})
                date = response.text
                if response.status_code==200:

                    datestamp = dateutil.parser.isoparse(date)
                    fix_dates.append(datestamp)
                else:
                    writer.writerow([cve, None, None, created_date])
            if len(fix_dates)>0:





                writer.writerow([cve, (fix_dates[-1] - created_date).days, fix_dates[-1], created_date])
                print(i, cve, (fix_dates[-1] - created_date).days, fix_dates[-1], created_date)
                continue

def patch_cve_libver_count():
    count =0
    with open('rq2_blocker/vul_lib_patch_date_diff.csv') as f, open('rq2_blocker/vul_gavs_count.csv', 'w') as fout:
        seen = set()
        writer = csv.writer(fout)
        for l in csv.reader(f):
            cve = l[0]
            if cve =='cve':
                continue
            if l[2]!= '':
                gavs = json.load(open('by_cve/' + cve + '/response.json'))
                if 'status' in gavs:
                    continue
                for gav in gavs:
                    if not gav['vendor']+'|'+gav['library']+'|'+gav['version'] in seen:
                        writer.writerow(gav['vendor']+'|'+gav['library']+'|'+gav['version'])
                        seen.add(gav['vendor']+'|'+gav['library']+'|'+gav['version'])

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

def non_patch_count_gav():
    count_lib_only('rq2_blocker/no_patch_gavs_count.csv')
    with open('rq2_blocker/vul_lib_patch_date_diff.csv') as f ,open('rq2_blocker/no_patch_gavs_count.csv', 'w') as fout:
        seen = set()
        writer = csv.writer(fout)
        for l in csv.reader(f):
            cve = l[0]
            if cve =='cve':
                continue
            if l[2]== '':
                gavs = json.load(open('by_cve/' + cve + '/response.json'))
                if 'status' in gavs:
                    continue
                for gav in gavs:
                    if not gav['vendor']+'|'+gav['library']+'|'+gav['version'] in seen:
                        writer.writerow([gav['vendor']+'|'+gav['library']+'|'+gav['version']])
                        seen.add(gav['vendor']+'|'+gav['library']+'|'+gav['version'])


