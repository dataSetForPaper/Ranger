import csv

import pymongo


def export_results(c, iter):
    with open(f'rq4_demo/exported_{iter}.csv', 'w') as fw:
        writer = csv.writer(fw)
        maven_range = c['library-crawler']['maven_range_only']
        for doc in maven_range.find():
            parent = doc['parent']
            dep = doc['dep']
            range = doc['range']
            if range == None:
                range = 'null'
            lvl = doc['depth']

            if int(lvl) == iter:
                writer.writerow([parent, dep, range, lvl, len(doc['callees'])])

# def export_accumulative():

