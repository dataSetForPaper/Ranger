import csv
import os
from datetime import datetime

import pandas as pd
import pymongo
import requests, json
from config import mongodb_host, mongodb_port, graph_api_host
import dateutil.parser

def get_log4j_versions():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    maven = c['library-crawler']['maven']
    for doc in maven.find({'group':"org.apache.logging.log4j", 'artifact':'log4j'}):
        print(doc['version'])


def get_all_vuls():
    response_file = 'all_vul_response.json'
    if os.path.exists(response_file) and os.path.getsize(response_file)>133:
        response = json.load(open(response_file))
    else:
        response = requests.post(f'http://{graph_api_host}:8090/dumpvuls', json={"platform": "maven"}).json()
        open(response_file, 'w').write(json.dumps(response))
    cves = set()
    # print(response)
    for each in response:
        # print(each)
        cves.add(each['vulnerabilityId'])
    return list(cves)


def get_log4j():
    if not os.path.exists('response_log4j_patch.json'):
        response = requests.post(f'http://{graph_api_host}:8090/log4j_patch', json={}).json()
        open('response_log4j_patch.json', 'w').write(json.dumps(response))
    if os.path.exists('response.json') and os.path.getsize('response.json')>133:

        response = json.load(open('response.json'))
    else:
        response = requests.post(f'http://{graph_api_host}:8090/log4j', json={}).json()
    open('response.json', 'w').write(json.dumps(response))
    ret = []
    chart = {}
    chart_by_month = {}
    ymds = set()
    yms = set()
    for each in response:
        date = each['proList'][0]['propertyContent']
        lvl = each['proList'][1]['propertyContent']
        if date>'2021-12-09':
            datestamp = dateutil.parser.isoparse(date)
            year_month = str(datestamp.year) +'-' + str(datestamp.month)
            month = str(datestamp.month)
            if len(month) == 1:
                month = '0'+month
            day = str(datestamp.day)
            if len(day) == 1:
                day = '0'+day
            ymd = str(datestamp.year) +'-' + month +'-'+ day
            ym = str(datestamp.year) +'-' + month
            ret.append(each)
            ymds.add(ymd)
            yms.add(ym)
            if lvl not in chart.keys():
                chart[lvl] = {}
            if ymd not in chart[lvl]:
                chart[lvl][ymd]= []
            chart[lvl][ymd].append(each)

            if lvl not in chart_by_month.keys():
                chart_by_month[lvl] = {}
            if ym not in chart_by_month[lvl]:
                chart_by_month[lvl][ym]= []
            chart_by_month[lvl][ym].append(each)

    ymds = ['2021-12-09','2021-12-10','2021-12-11','2021-12-12','2021-12-13','2021-12-14','2021-12-15','2021-12-16','2021-12-17','2021-12-18','2021-12-19','2021-12-20','2021-12-21','2021-12-22','2021-12-23','2021-12-24','2021-12-25','2021-12-26','2021-12-27','2021-12-28','2021-12-29','2021-12-30','2021-12-31','2022-01-01','2022-01-02','2022-01-03','2022-01-04','2022-01-05','2022-01-06','2022-01-07','2022-01-08','2022-01-09','2022-01-10','2022-01-11','2022-01-12','2022-01-13','2022-01-14','2022-01-15','2022-01-16','2022-01-17','2022-01-18','2022-01-19','2022-01-20','2022-01-21','2022-01-22','2022-01-23','2022-01-24','2022-01-25','2022-01-26','2022-01-27','2022-01-28','2022-01-29','2022-01-30','2022-01-31','2022-02-01','2022-02-02','2022-02-03','2022-02-04','2022-02-05','2022-02-06','2022-02-07','2022-02-08','2022-02-09','2022-02-10','2022-02-11','2022-02-12','2022-02-13','2022-02-14','2022-02-15','2022-02-16','2022-02-17','2022-02-18','2022-02-19','2022-02-20','2022-02-21','2022-02-22','2022-02-23','2022-02-24','2022-02-25','2022-02-26','2022-02-27','2022-02-28','2022-03-01','2022-03-02','2022-03-03','2022-03-04','2022-03-05','2022-03-06','2022-03-07','2022-03-08','2022-03-09','2022-03-10','2022-03-11','2022-03-12','2022-03-13','2022-03-14','2022-03-15','2022-03-16','2022-03-17','2022-03-18','2022-03-19','2022-03-20','2022-03-21','2022-03-22','2022-03-23','2022-03-24','2022-03-25','2022-03-26','2022-03-27','2022-03-28','2022-03-29','2022-03-30','2022-03-31','2022-04-01','2022-04-02','2022-04-03','2022-04-04','2022-04-05','2022-04-06','2022-04-07','2022-04-08','2022-04-09','2022-04-10','2022-04-11','2022-04-12','2022-04-13','2022-04-14','2022-04-15','2022-04-16','2022-04-17','2022-04-18','2022-04-19','2022-04-20','2022-04-21','2022-04-22','2022-04-23','2022-04-24','2022-04-25','2022-04-26','2022-04-27','2022-04-28','2022-04-29','2022-04-30','2022-05-01','2022-05-02','2022-05-03','2022-05-04','2022-05-05','2022-05-06','2022-05-07','2022-05-08','2022-05-09','2022-05-10','2022-05-11','2022-05-12','2022-05-13','2022-05-14','2022-05-15','2022-05-16','2022-05-17','2022-05-18','2022-05-19','2022-05-20','2022-05-21','2022-05-22','2022-05-23','2022-05-24','2022-05-25','2022-05-26','2022-05-27','2022-05-28','2022-05-29','2022-05-30','2022-05-31','2022-06-01','2022-06-02','2022-06-03','2022-06-04','2022-06-05','2022-06-06','2022-06-07','2022-06-08','2022-06-09','2022-06-10','2022-06-11','2022-06-12','2022-06-13','2022-06-14','2022-06-15','2022-06-16','2022-06-17','2022-06-18','2022-06-19','2022-06-20','2022-06-21','2022-06-22','2022-06-23','2022-06-24','2022-06-25','2022-06-26','2022-06-27','2022-06-28','2022-06-29','2022-06-30','2022-07-01','2022-07-02','2022-07-03','2022-07-04','2022-07-05','2022-07-06','2022-07-07','2022-07-08','2022-07-09','2022-07-10','2022-07-11','2022-07-12','2022-07-13','2022-07-16','2022-07-20','2022-07-25','2022-07-26','2022-07-27','2022-07-28','2022-07-29','2022-07-30','2022-07-31','2022-08-01','2022-08-02','2022-08-03','2022-08-04','2022-08-05','2022-08-06','2022-08-07','2022-08-08','2022-08-09','2022-08-10','2022-08-11','2022-08-12','2022-08-13','2022-08-14','2022-08-15','2022-08-16','2022-08-17','2022-08-18','2022-08-19','2022-08-20','2022-08-21','2022-08-22','2022-08-23','2022-08-24','2022-08-25','2022-08-26','2022-08-27','2022-08-28','2022-09-07','2022-09-08','2022-09-09','2022-09-10','2022-09-11','2022-09-12','2022-09-13','2022-09-14','2022-09-15','2022-09-16','2022-09-17','2022-09-18','2022-09-19','2022-09-20','2022-09-21','2022-09-22','2022-09-23','2022-09-24','2022-09-25','2022-09-26','2022-09-27','2022-09-28','2022-09-29','2022-09-30','2022-10-01','2022-10-02','2022-10-03','2022-10-04','2022-10-05','2022-10-06','2022-10-07','2022-10-08','2022-10-09','2022-10-10','2022-10-11','2022-10-12','2022-10-13','2022-10-14','2022-10-15','2022-10-16','2022-10-17','2022-10-18','2022-10-19','2022-10-20','2022-10-21','2022-10-22','2022-10-23','2022-10-24','2022-10-25','2022-10-26','2022-10-27','2022-10-28','2022-10-29','2022-10-30','2022-10-31','2022-11-01','2022-11-02','2022-11-03','2022-11-04','2022-11-05','2022-11-06','2022-11-07','2022-11-08','2022-11-09','2022-11-10','2022-11-11','2022-11-12','2022-11-13','2022-11-14','2022-11-15','2022-11-16','2022-11-17','2022-11-18','2022-11-19','2022-11-20','2022-11-21','2022-11-22','2022-11-23','2022-11-24','2022-11-25','2022-11-26','2022-11-27','2022-11-28','2022-11-29','2022-11-30','2022-12-01','2022-12-02','2022-12-03','2022-12-04','2022-12-05','2022-12-06','2022-12-07','2022-12-08','2022-12-09','2022-12-10','2022-12-11','2022-12-12','2022-12-13','2022-12-14','2022-12-15','2022-12-16','2022-12-17','2022-12-19','2022-12-20','2022-12-21','2022-12-22','2022-12-23','2022-12-24','2022-12-25','2022-12-27','2022-12-28','2022-12-29','2022-12-30','2023-01-01','2023-01-02','2023-01-03','2023-01-04','2023-01-05','2023-01-06','2023-01-07','2023-01-08','2023-01-09','2023-01-10','2023-01-11', "2023-01-12","2023-01-13","2023-01-14","2023-01-15","2023-01-16","2023-01-17","2023-01-18","2023-01-19","2023-01-20","2023-01-21","2023-01-22","2023-01-23","2023-01-24","2023-01-25","2023-01-26","2023-01-27","2023-01-28","2023-01-29","2023-01-30","2023-01-31","2023-02-01","2023-02-02","2023-02-03","2023-02-04","2023-02-05","2023-02-06","2023-02-07","2023-02-08","2023-02-09","2023-02-10","2023-02-11","2023-02-12","2023-02-13","2023-02-14","2023-02-15","2023-02-16","2023-02-17","2023-02-18","2023-02-19","2023-02-20","2023-02-21","2023-02-22","2023-02-23","2023-02-24","2023-02-25","2023-02-26","2023-02-27","2023-02-28","2023-03-01","2023-03-02","2023-03-03","2023-03-04","2023-03-05","2023-03-06","2023-03-07","2023-03-08","2023-03-09","2023-03-10","2023-03-11","2023-03-12","2023-03-13","2023-03-14","2023-03-15","2023-03-16","2023-03-17","2023-03-18","2023-03-19","2023-03-20","2023-03-21","2023-03-22","2023-03-23","2023-03-24","2023-03-25","2023-03-26","2023-03-27","2023-03-28","2023-03-29","2023-03-30","2023-03-31","2023-04-01"]

    yms = list(yms)
    yms.sort()
    df = pd.DataFrame(index=['1','2','3', '4', '5', '6','7', '8', '9', '10', '11'], columns=yms)#['2021-12','2022-1', '2022-2', '2022-3', '2022-4', '2022-5', '2022-6', '2022-7', '2022-8', '2022-9', '2022-10', '2022-11'])
    for lvl in chart_by_month:
        for year_month in chart_by_month[lvl]:
   
            df.at[lvl, year_month] = len(chart_by_month[lvl][year_month])
    df = df.fillna(0)

    df.to_csv('log4j_per_month.csv')
    df = pd.DataFrame(index=['1','2','3', '4', '5', '6','7', '8', '9', '10', '11'], columns=ymds)#['2021-12','2022-1', '2022-2', '2022-3', '2022-4', '2022-5', '2022-6', '2022-7', '2022-8', '2022-9', '2022-10', '2022-11'])
    for lvl in chart:
        for year_month_day in chart[lvl]:

            df.at[lvl, year_month_day] = int(len(chart[lvl][year_month_day]))
    df = df.fillna(0)

    df.to_csv('log4j_per_day.csv')
    with open('log4j_per_day.csv') as fr,  open('log4j_per_week.csv', 'w') as fw:
        writer = csv.writer(fw)
        for i, line in enumerate(csv.reader(fr)):
            if i != 0:
                count = 0
                one_line = []
                tmp = 0
                for col in line:
                    if count < 7:
                        count += 1
                        tmp += float(col)
                    else:
                        one_line.append(tmp)
                        tmp = 0
                        count = 0
                writer.writerow(one_line)
    with open('response.json') as f, open('response.csv', 'w') as f2:
        writer = csv.writer(f2)
        for e in json.load(f):
            writer.writerow([e['vendor'], e['library'], e['version']])

def analyze_all_vuls():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    modified_date = '2023-02-03'
    if not os.path.exists('cves.json'):
        cves = get_all_vuls()
        with open('cves.json', 'w') as f:
            f.write(json.dumps(cves))
    else:
        cves = json.load(open('cves.json'))

    print('To be processed cves:', len(cves))
    os.makedirs('by_cve', exist_ok=True)
    for i, cve in enumerate(cves):
        print(i, cve)

        if not cve_created_time.find_one({'cve': cve}):
            continue
        os.makedirs('by_cve/'+cve, exist_ok=True)

        print(str(datetime.fromtimestamp((os.path.getmtime('by_cve/'+cve+'/response.json')))))

        if os.path.exists('by_cve/'+cve+'/response.json') and str(datetime.fromtimestamp((os.path.getmtime('by_cve/'+cve+'/response.json'))))>modified_date:

            response = json.load(open('by_cve/'+cve+'/response.json'))
            if 'status' in response:
                response = requests.post(f'http://{graph_api_host}:8090/oneVulAnalysis', json={"vulnerabilityId": cve}).json()
                open('by_cve/' + cve + '/response.json', 'w').write(json.dumps(response))

        else:
            response = requests.post(f'http://{graph_api_host}:8090/oneVulAnalysis', json={"vulnerabilityId": cve}).json()
            open('by_cve/'+cve+'/response.json', 'w').write(json.dumps(response))
        if 'status' in response:
            print('Failed', cve)
            continue

        ret = []
        chart = {}
        chart_by_month = {}
        ymds = set()
        yms = set()
        for each in response:
            date = each['proList'][0]['propertyContent']
            lvl = each['proList'][1]['propertyContent']

            datestamp = dateutil.parser.isoparse(date)
            year_month = str(datestamp.year) + '-' + str(datestamp.month)
            month = str(datestamp.month)
            if len(month) == 1:
                month = '0' + month
            day = str(datestamp.day)
            if len(day) == 1:
                day = '0' + day
            ymd = str(datestamp.year) + '-' + month + '-' + day
            ym = str(datestamp.year) + '-' + month
            ret.append(each)
            ymds.add(ymd)
            yms.add(ym)
            if lvl not in chart.keys():
                chart[lvl] = {}
            if ymd not in chart[lvl]:
                chart[lvl][ymd] = []
            chart[lvl][ymd].append(each)

            if lvl not in chart_by_month.keys():
                chart_by_month[lvl] = {}
            if ym not in chart_by_month[lvl]:
                chart_by_month[lvl][ym] = []
            chart_by_month[lvl][ym].append(each)
        ymds = list(ymds)
        yms = list(yms)
        yms.sort()
        ymds.sort()
        df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'],
                          columns=yms)  # ['2021-12','2022-1', '2022-2', '2022-3', '2022-4', '2022-5', '2022-6', '2022-7', '2022-8', '2022-9', '2022-10', '2022-11'])
        for lvl in chart:
            for year_month in chart_by_month[lvl]:
                df.at[lvl, year_month] = len(chart_by_month[lvl][year_month])
        df = df.fillna(0)

        try:
            df.loc['Total'] = df.sum(numeric_only=True)
        except ValueError:
            continue
        df.to_csv('by_cve/'+cve+'/results_by_month.csv')

        df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'],
                          columns=ymds)  
        for lvl in chart:
            for year_month_day in chart[lvl]:

                df.at[lvl, year_month_day] = len(chart[lvl][year_month_day])
        df = df.fillna(0)

        try:
            df.loc['Total'] = df.sum(numeric_only=True)
        except ValueError:
            continue
        df.to_csv('by_cve/' + cve + '/results_by_day.csv')


    c.close()


def analyze_all_patches():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    modified_date = '2022-12-15'
    if not os.path.exists('cves.json'):
        cves = get_all_vuls()
        with open('cves.json', 'w') as f:
            f.write(json.dumps(cves))
    else:
        cves = json.load(open('cves.json'))

    print('To be processed cves:', len(cves))
    os.makedirs('by_cve', exist_ok=True)
    for i, cve in enumerate(cves):
        print(i, cve)
        if not cve_created_time.find_one({'cve': cve}):
            continue
        os.makedirs('by_cve/'+cve, exist_ok=True)

        if os.path.exists('by_cve/'+cve+'/response_patch.json') and str(datetime.fromtimestamp((os.path.getmtime('by_cve/'+cve+'/response_patch.json'))))>modified_date:
            response = json.load(open('by_cve/'+cve+'/response_patch.json'))

        else:
            response = requests.post(f'http://{graph_api_host}:8090/onePatchAnalysis', json={"vulnerabilityId": cve}).json()
            open('by_cve/'+cve+'/response_patch.json', 'w').write(json.dumps(response))
        if 'status' in response:
            print('Failed', cve)
            continue


        if os.path.exists('by_cve/'+cve+'/results_patch_by_day.csv') and str(datetime.fromtimestamp((os.path.getmtime('by_cve/'+cve+'/results_patch_by_day.csv'))))>modified_date:
            continue
        ret = []
        chart = {}
        chart_by_month = {}
        ymds = set()
        yms = set()
        for each in response:
            # print(response2.json())
            date = each['proList'][0]['propertyContent']
            lvl = each['proList'][1]['propertyContent']

            datestamp = dateutil.parser.isoparse(date)
            year_month = str(datestamp.year) + '-' + str(datestamp.month)
            month = str(datestamp.month)
            if len(month) == 1:
                month = '0' + month
            day = str(datestamp.day)
            if len(day) == 1:
                day = '0' + day
            ymd = str(datestamp.year) + '-' + month + '-' + day
            ym = str(datestamp.year) + '-' + month
            ret.append(each)
            ymds.add(ymd)
            yms.add(ym)
            if lvl not in chart.keys():
                chart[lvl] = {}
            if ymd not in chart[lvl]:
                chart[lvl][ymd] = []
            chart[lvl][ymd].append(each)

            if lvl not in chart_by_month.keys():
                chart_by_month[lvl] = {}
            if ym not in chart_by_month[lvl]:
                chart_by_month[lvl][ym] = []
            chart_by_month[lvl][ym].append(each)
        ymds = list(ymds)
        yms = list(yms)
        yms.sort()
        ymds.sort()
        df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'],
                          columns=yms)  
        for lvl in chart:
            for year_month in chart_by_month[lvl]:

                df.at[lvl, year_month] = len(chart_by_month[lvl][year_month])
        df = df.fillna(0)

        try:
            df.loc['Total'] = df.sum(numeric_only=True)
        except ValueError:
            continue
        df.to_csv('by_cve/'+cve+'/results_patch_by_month.csv')

        df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'],
                          columns=ymds)  
        for lvl in chart:
            for year_month_day in chart[lvl]:

                df.at[lvl, year_month_day] = len(chart[lvl][year_month_day])
        df = df.fillna(0)

        try:
            df.loc['Total'] = df.sum(numeric_only=True)
        except ValueError:
            continue
        df.to_csv('by_cve/' + cve + '/results_patch_by_day.csv')


    c.close()

def get_blockers_affected():
    if os.path.exists('response.json'):
        response = json.load(open('response.json'))
    else:
        response = requests.post('http://localhost:8090/log4j', json={}).json()
        open('response.json', 'w').write(json.dumps(response))
    with open('rq2_blocker/log4j_blockers.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['gav', 'release_date', 'versions', 'max lvl', 'max date', 'span'])
        visited = set()
        for each in response:

            date = each['proList'][0]['propertyContent']
            lvl = each['proList'][1]['propertyContent']
            if date > '2021-12-09' and lvl =='1':
                name = each['library']
                vendor = each['vendor']
                version = each['version']
                if vendor+'|'+name+'|'+version == 'org.wso2.carbon.identity.framework|org.wso2.carbon.identity.testutil|5.18.236':
                    a =9
                print(vendor+'|'+name+'|'+version)
                if vendor+'|'+name+'|'+version in visited:
                    continue
                response = requests.post('http://localhost:8090/findBlockersAffections', json={"platform": "maven",
                    "vendor": vendor,
                    "name": name,
                    "version": version}).json()
                max_lvl = 0
                max_date = ''
                for victim in response:
                    current_lvl = int(victim['proList'][1]['propertyContent'])
                    if victim['proList'][0]['propertyContent'] <= '2021-12-09':
                        continue
                    if current_lvl>max_lvl:
                        max_lvl = current_lvl
                    if victim['proList'][0]['propertyContent'] > max_date:
                        max_date = victim['proList'][0]['propertyContent']
                if max_date:
                    end = dateutil.parser.isoparse(max_date)
                    start = dateutil.parser.isoparse(date)
                    span = int((end - start).total_seconds()/60/60/24)
                    if span ==0:
                        span =1
                else:
                    span = 0
                writer.writerow([vendor+'|'+name+'|'+version, date, len(response), max_lvl, max_date, span])
                visited.add(vendor+'|'+name+'|'+version)


