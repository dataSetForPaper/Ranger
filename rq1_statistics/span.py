import csv
import os
from datetime import datetime

import dateutil
import pymongo

from config import mongodb_host, mongodb_port


def span():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    result = {}
    result2 = {}
    release_dates = {}
    for folder in os.listdir('by_cve'):
        cve = folder
        print(cve)
        if not os.path.exists('by_cve/'+folder+'/results_by_day.csv'):
            continue
        with open('by_cve/'+folder+'/results_by_day.csv') as f:
            doc = cve_created_time.find_one({'cve': cve})
            if doc:
                time = doc['time'].replace('.', '-')
                release_dates[cve] = time
            else:
                time = None
                release_dates[cve] = ''
            if time:
                date_line = []
                for i, line in enumerate(csv.reader(f)):
                    if i == 0:
                        date_line = line
                    if line[0]=='Total':
                        count = 0
                        last = ''
                        for j, each in enumerate(line):
                            if j == 0:
                                continue
                            if time:
                                if time <= date_line[j] and each != '0':
                                    last = date_line[j]
                            else:
                                continue
                if last == '':
                    result[folder] = 0
                    result2[folder] = 0
                else:

                    result[folder]= (dateutil.parser.isoparse(last) - dateutil.parser.isoparse(time)).days
                    result2[folder]= result[folder]/((datetime.now() - dateutil.parser.isoparse(time)).days)
    with open('rq1_statistics/span.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['cve', 'release_date', 'span', 'span_distribution'])
        for cve in result:
            writer.writerow([cve, release_dates[cve], result[cve], result2[cve]])


    c.close()


def span_distribution():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    result = {}
    for folder in os.listdir('by_cve'):
        cve = folder
        if not os.path.exists('by_cve/'+folder+'/results_by_day.csv'):
            continue
        with open('by_cve/'+folder+'/results_by_day.csv') as f:
            doc = cve_created_time.find_one({'cve': cve})
            if doc:
                time = doc['time'].replace('.', '-')
            else:
                time = None
            date_line = []
            for i, line in enumerate(csv.reader(f)):
                if i == 0:
                    date_line = line
                if line[0]=='Total':
                    count = 0
                    for j, each in enumerate(line):
                        if j == 0 :
                            continue
                        if time:
                            if time <= date_line[j] and each != '0':
                                count += 1
                        else:
                            continue


    with open('span_distribution.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['cve', 'span'])
        for cve in result:
            writer.writerow([cve, result[cve]])
    c.close()