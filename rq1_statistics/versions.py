import csv
import os

import pymongo

from config import mongodb_host, mongodb_port

def versions():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    result = {}
    result2 = {}
    release_dates = {}
    for folder in os.listdir('by_cve'):
        cve = folder
        print(folder)
        if not os.path.exists('by_cve/'+folder+'/results_by_month.csv'):
            continue
        with open('by_cve/'+folder+'/results_by_month.csv') as f:
            doc = cve_created_time.find_one({'cve': cve})
            if doc:
                time = doc['time'].replace('.', '-')
                release_dates[cve] = time
            else:
                time = None
                release_dates[cve] = ''
            date_line = []
            for i, line in enumerate(csv.reader(f)):
                if i == 0:
                    date_line = line
                if line[0]=='Total':
                    count = 0
                    largest = 0
                    for j, each in enumerate(line):
                        if j == 0:
                            continue
                        if largest<int(each):
                            largest = int(each)
                        if time:
                            if time <= date_line[j] and each != '0':
                                count += int(each)
                        else:
                            continue
            result[folder]=count
            result2[folder] = largest

    with open('rq1_statistics/versions.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['cve', 'release_date', 'versions', 'peak'])
        for cve in result:
            writer.writerow([cve, release_dates[cve], result[cve], result2[cve]])

    c.close()