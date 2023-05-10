import csv
import os

import pymongo

from config import mongodb_host, mongodb_port


def depth():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    result = {}

    release_dates = {}
    for folder in os.listdir('by_cve'):
        cve = folder
        print(cve)
        if not os.path.exists('by_cve/'+folder+'/results.csv'):
            continue
        with open('by_cve/'+folder+'/results.csv') as f:
            doc = cve_created_time.find_one({'cve': cve})
            if doc:
                time = doc['time'].replace('.', '-')
                release_dates[cve] = time
            else:
                release_dates[cve] = ''

            depth = 0
            for i, line in enumerate(csv.reader(f)):
                if i == 0:
                    date_line = line
                if line[0] == 'Total':
                    continue
                if_depth = False
                for j, each in enumerate(line):
                    if j == 0:
                        continue
                    if time and each !='0' and time <= date_line[j]:
                        if_depth = True
                        break
                if if_depth:
                    depth+=1
                else:
                    break
            result[folder]=depth

    with open('rq1_statistics/depth.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['cve', 'release_date', 'depth'])
        for cve in result:
            writer.writerow([cve, release_dates[cve], result[cve]])


    c.close()

