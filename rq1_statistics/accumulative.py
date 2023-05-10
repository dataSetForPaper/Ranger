import csv
import json
import os
from collections import defaultdict
from datetime import datetime
import re

import dateutil
import pandas
import pandas as pd
import pymongo
from config import mongodb_host, mongodb_port

def accumulative(exclusive=None):
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    release_dates = {}
    for folder in os.listdir('by_cve'):
        cve = folder
        print(cve)
        if exclusive and cve !=exclusive:
            continue
        if not os.path.exists('by_cve/'+folder+'/response.json') or not os.path.exists('by_cve/'+folder+'/response_patch.json'):
            continue
        with open('by_cve/'+folder+'/response.json') as f, open('by_cve/'+folder+'/response_patch.json') as pf:
            libvers = json.load(f)
            patch_libvers = json.load(pf)
            if 'status' in libvers or 'status' in patch_libvers:
                continue
            doc = cve_created_time.find_one({'cve': cve})
            if doc:
                time = doc['time'].replace('.', '-')
                release_dates[cve] = time
            else:
                time = None
                release_dates[cve] = ''
            if time:
                gavs = defaultdict(list)
                time_vul = defaultdict(list)
                for libver in libvers:
                    date = libver['proList'][0]['propertyContent']
                    lvl = libver['proList'][1]['propertyContent']
                    gavs[libver['vendor']+'|'+libver['library']].append({
                        'ver':libver['version'],
                        'release': date,
                        'lvl': lvl
                    })
                    time_vul[date.split(' ')[0]].append(libver['vendor']+'|'+libver['library']+'|'+libver['version']+'|'+lvl)
                time_patch = defaultdict(list)
                patch_gavs = defaultdict(list)
                for libver in patch_libvers:
                    date = libver['proList'][0]['propertyContent']
                    lvl = libver['proList'][1]['propertyContent']
                    patch_gavs[libver['vendor']+'|'+libver['library']].append({
                        'ver':libver['version'],
                        'release': date,
                        'lvl': lvl
                    })
                    time_patch[date.split(' ')[0]].append(
                        libver['vendor'] + '|' + libver['library'] + '|' + libver['version']+'|'+lvl)
                asc_dates = list(time_vul.keys())+list(time_patch.keys())
                asc_dates = list(set(asc_dates))
                asc_dates.sort()
                months = list()
                for date in asc_dates:
                    if re.sub('-\d+$', '', date) not in months:
                        months.append(re.sub('-\d+$', '', date))
                vul_gas = set()
                patched_gas = set()
                vul_count_df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=months)
                vul_df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=months)
                df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=asc_dates)
                patch_df = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=months)
                per_lvl = dict.fromkeys(['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'])
                for each_lvl in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']:
                    per_lvl[each_lvl] = [set(), set()]
                for each_date in asc_dates:
                    # if each_date < '2021-12-09':
                    #     continue
                    each_month = re.sub('-\d+$', '', each_date)
                    if each_date in time_patch:
                        for gav_patch in time_patch[each_date]:
                            g,a,v, l = gav_patch.split('|')
                            if g+'|'+a in vul_gas:
                                vul_gas.remove(g+'|'+a)
                                if g+'|'+a in per_lvl[l][0]:
                                    per_lvl[l][0].remove(g+'|'+a)
                            patched_gas.add(g+'|'+a)
                            per_lvl[l][1].add(g+'|'+a)
                    if each_date in time_vul:
                        for gav_vul in time_vul[each_date]:
                            g,a,v, l = gav_vul.split('|')
                            if g+'|'+a in patched_gas:
                                patched_gas.remove(g+'|'+a)
                                if g+'|'+a in per_lvl[l][1]:
                                    per_lvl[l][1].remove(g+'|'+a)
                            vul_gas.add(g+'|'+a)
                            per_lvl[l][0].add(g+'|'+a)
                    for lvl in per_lvl.keys():
                        if each_month in months:
                            vul_count_df.at[lvl, each_month] = len(per_lvl[lvl][0])
                        if len(per_lvl[lvl][0])+len(per_lvl[lvl][1]) ==0:
                            df.at[lvl, each_date] =0
                            if each_month in months:
                                vul_df.at[lvl, each_month] = 0
                        else:
                            df.at[lvl, each_date] =len(per_lvl[lvl][0])/(len(per_lvl[lvl][0])+len(per_lvl[lvl][1]))
                            if each_month in months:
                                vul_df.at[lvl, each_month] = len(per_lvl[lvl][0])/(len(per_lvl[lvl][0])+len(per_lvl[lvl][1]))
                                patch_df.at[lvl, each_month] = len(per_lvl[lvl][1]) / (
                                            len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]))
                    if each_month in months:
                        vul_count_df.at['Total', each_month] = len(vul_gas)

                    if len(vul_gas)+len(patched_gas)==0:
                        df.at['Total', each_date] = 0
                        if each_month in months:
                            vul_df.at['Total', each_month] = 0
                    else:
                        df.at['Total', each_date] = len(vul_gas)/(len(vul_gas)+len(patched_gas))
                        if each_month in months:
                            patch_df.at['Total', each_month]= len(patched_gas)/(len(vul_gas)+len(patched_gas))
                            vul_df.at['Total', each_month]= len(vul_gas)/(len(vul_gas)+len(patched_gas))
                vul_df.fillna(0)
                vul_count_df.fillna(0)
                df = df.fillna(0)
                vul_count_df.to_csv('by_cve/' + cve + '/accumulative_count_by_month.csv')
                vul_df.to_csv('by_cve/' + cve + '/accumulative_by_month.csv')
                df.to_csv('by_cve/' + cve + '/accumulative_by_day.csv')

        # break
    c.close()

def unfound_version_fix_time(maven, g, a, vers, latest_date):
    for doc in maven.find({'group': g, 'artifact': a}):
        if doc['version'] not in vers:
            current_date = str(datetime.fromtimestamp(int(doc['time']) / 1000)).split(' ')[0]
            # print(current_date)
            if current_date> '2021-12-01' and current_date>latest_date:
                return current_date, doc['version']
    return None, None




def accumulative_log4j():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    maven = c['library-crawler']['maven']
    maven.create_index([("group", pymongo.ASCENDING), ("artifact", pymongo.ASCENDING)])
    maven.create_index([("group", pymongo.ASCENDING), ("artifact", pymongo.ASCENDING), ("version", pymongo.ASCENDING)])
    release_dates = {}
    for folder in os.listdir('by_cve'):
        cve = folder
        print(cve)
        if not os.path.exists('by_cve/' + folder + '/response.json') or not os.path.exists(
                'by_cve/' + folder + '/response_patch.json'):
            continue
        # if os.path.exists('by_cve/'+folder+'/accumulative_by_day.csv'):
        #     continue
        with open('by_cve/' + folder + '/response.json') as f, open(
                'by_cve/' + folder + '/response_patch.json') as pf:
            libvers = json.load(f)
            patch_libvers = json.load(pf)
            if 'status' in libvers or 'status' in patch_libvers:
                continue
            doc = cve_created_time.find_one({'cve': cve})
            if doc:
                time = doc['time'].replace('.', '-')
                release_dates[cve] = time
            else:
                time = None
                release_dates[cve] = ''
            if time:
                unique_vers = defaultdict(set)
                gavs = defaultdict(list)
                time_vul = defaultdict(list)
                for libver in libvers:
                    date = libver['proList'][0]['propertyContent']
                    lvl = libver['proList'][1]['propertyContent']
                    unique_vers[libver['vendor'] + '|' + libver['library']].add(libver['version'])
                    gavs[libver['vendor'] + '|' + libver['library']].append({
                        'ver': libver['version'],
                        'release': date,
                        'lvl': lvl
                    })
                    time_vul[date.split(' ')[0]].append(
                        libver['vendor'] + '|' + libver['library'] + '|' + libver['version'] + '|' + lvl)
                time_patch = defaultdict(list)
                patch_gavs = defaultdict(list)
                for libver in patch_libvers:
                    date = libver['proList'][0]['propertyContent']
                    lvl = libver['proList'][1]['propertyContent']
                    unique_vers[libver['vendor'] + '|' + libver['library']].add(libver['version'])
                    time_patch[date.split(' ')[0]].append(
                        libver['vendor'] + '|' + libver['library'] + '|' + libver['version'] + '|' + lvl)
                unfound_time = json.load(open('rq1_statistics/unfound_time.json'))
                asc_dates = list(time_vul.keys()) + list(time_patch.keys())+ list(unfound_time.keys())
                asc_dates = list(set(asc_dates))
                asc_dates.sort()

                months = list()
                for date in asc_dates:
                    if re.sub('-\d+$', '', date) not in months:
                        months.append(re.sub('-\d+$', '', date))
                vul_gas = set()
                patched_gas = set()
                unfound_gas = set()
                vul_count_df_by_month = pd.DataFrame(
                    index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                    columns=months)
                vul_df_by_month = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                      columns=months)
                df_by_day = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=asc_dates)
                patch_df_by_day = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=asc_dates)
                unfound_df_by_day = pd.DataFrame(index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                                  columns=asc_dates)
                per_lvl = dict.fromkeys(['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'])
                for each_lvl in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']:
                    per_lvl[each_lvl] = [set(), set(), set()]

                for each_date in asc_dates:
                    each_month = re.sub('-\d+$', '', each_date)
                    if each_date in time_patch:
                        for gav_patch in time_patch[each_date]:
                            g, a, v, l = gav_patch.split('|')
                            if g + '|' + a in vul_gas:
                                vul_gas.remove(g + '|' + a)
                                if g + '|' + a in per_lvl[l][0]:
                                    per_lvl[l][0].remove(g + '|' + a)
                            patched_gas.add(g + '|' + a)
                            per_lvl[l][1].add(g + '|' + a)
                    if each_date in time_vul:
                        for gav_vul in time_vul[each_date]:
                            g, a, v, l = gav_vul.split('|')
                            if g + '|' + a in patched_gas:
                                patched_gas.remove(g + '|' + a)
                                if g + '|' + a in per_lvl[l][1]:
                                    per_lvl[l][1].remove(g + '|' + a)
                            vul_gas.add(g + '|' + a)
                            per_lvl[l][0].add(g + '|' + a)
                    if each_date in unfound_time.keys():
                        for gav_unfound in unfound_time[each_date]:
                            g, a, v, l = gav_unfound.split('|')
                            if g + '|' + a in vul_gas:
                                vul_gas.remove(g + '|' + a)
                                if g + '|' + a in per_lvl[l][0]:
                                    per_lvl[l][0].remove(g + '|' + a)
                            unfound_gas.add(g + '|' + a)
                            per_lvl[l][2].add(g + '|' + a)


                    for lvl in per_lvl.keys():
                        if each_month in months:
                            vul_count_df_by_month.at[lvl, each_month] = len(per_lvl[lvl][0])
                        if len(per_lvl[lvl][0]) + len(per_lvl[lvl][1])+ len(per_lvl[lvl][2]) == 0:
                            df_by_day.at[lvl, each_date] = 0
                            patch_df_by_day.at[lvl, each_month] = 0
                            unfound_df_by_day.at[lvl, each_month] = 0
                            if each_month in months:
                                vul_df_by_month.at[lvl, each_month] = 0

                        else:
                            df_by_day.at[lvl, each_date] = len(per_lvl[lvl][0]) / (
                                        len(per_lvl[lvl][0]) + len(per_lvl[lvl][1])+ len(per_lvl[lvl][2]))
                            patch_df_by_day.at[lvl, each_date] = len(per_lvl[lvl][1]) / (
                                    len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]))
                            unfound_df_by_day.at[lvl, each_date] = len(per_lvl[lvl][2]) / (
                                    len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]))
                            if each_month in months:
                                vul_df_by_month.at[lvl, each_month] = len(per_lvl[lvl][0]) / (
                                            len(per_lvl[lvl][0]) + len(per_lvl[lvl][1])+ len(per_lvl[lvl][2]))
                    if each_month in months:
                        vul_count_df_by_month.at['Total', each_month] = len(vul_gas)

                    if len(vul_gas) + len(patched_gas) +len(unfound_gas)== 0:
                        df_by_day.at['Total', each_date] = 0
                        patch_df_by_day.at['Total', each_date] = 0
                        unfound_df_by_day.at['Total', each_date] = 0
                        if each_month in months:
                            vul_df_by_month.at['Total', each_month] = 0
                    else:
                        df_by_day.at['Total', each_date] = len(vul_gas) / (len(vul_gas) + len(patched_gas)+len(unfound_gas))
                        patch_df_by_day.at['Total', each_date] = len(patched_gas) / (
                                    len(vul_gas) + len(patched_gas) + len(unfound_gas))
                        unfound_df_by_day.at['Total', each_date] = len(unfound_gas) / (
                                    len(vul_gas) + len(patched_gas) + len(unfound_gas))
                        if each_month in months:
                            vul_df_by_month.at['Total', each_month] = len(vul_gas) / (len(vul_gas) + len(patched_gas)+len(unfound_gas))
                vul_df_by_month.fillna(0)
                vul_count_df_by_month.fillna(0)
                df_by_day = df_by_day.fillna(0)
                vul_count_df_by_month.to_csv('by_cve/' + cve + '/accumulative_count_by_month.csv')
                vul_df_by_month.to_csv('by_cve/' + cve + '/accumulative_by_month.csv')
                df_by_day = df_by_day.loc[:, '2021-12-09':]
                df_by_day.to_csv('by_cve/' + cve + '/accumulative_by_day.csv')
                patch_df_by_day = patch_df_by_day.loc[:, '2021-12-09':]
                patch_df_by_day.to_csv('by_cve/' + cve + '/accumulative_patch_by_day.csv')
                unfound_df_by_day = unfound_df_by_day.loc[:, '2021-12-09':]
                unfound_df_by_day.to_csv('by_cve/' + cve + '/accumulative_unfound_by_day.csv')


        break
    c.close()

def full_life():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    for cve in os.listdir('by_cve'):
        if 'SEC' in cve or 'CNNVD' in cve or 'CNVD' in cve:
            continue
        if not os.path.exists('by_cve/'+cve+'/accumulative_by_day.csv'):
            continue

        doc = cve_created_time.find_one({'cve': cve})
        if doc:
            time = doc['time'].replace('.', '-')
        else:
            time = None
        if time:
            span = 0
            affected_versions = len(json.load(open('by_cve/'+cve+'/response.json')))
            df = pandas.read_csv('by_cve/'+cve+'/accumulative_by_day.csv')
            full_time = ''
            for date, colum in df.items():
                if '-' not in date:
                    continue
                if colum[len(colum)-1]==0:
                    full_time = date
                    break
            with open('rq1_statistics/full_life.csv', 'a') as f:
                life_time = (datetime.strptime('2023-01-01', '%Y-%m-%d') - datetime.strptime(time, '%Y-%m-%d')).days
                if full_time:
                    # print(half_time, time)
                    half_lifE = (datetime.strptime(full_time, '%Y-%m-%d') - datetime.strptime(time, '%Y-%m-%d')).days
                    # print(half_lifE)
                    csv.writer(f).writerow([cve, half_lifE/life_time, half_lifE, full_time, time, affected_versions])

                else:
                    half_lifE = 'inf'
                    csv.writer(f).writerow([cve, 1, half_lifE, full_time, time, affected_versions])
def half_life():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    cve_created_time = c['library-crawler']['cve_created_time']
    for cve in os.listdir('by_cve'):
        if not os.path.exists('by_cve/'+cve+'/accumulative_by_day.csv'):
            continue

        doc = cve_created_time.find_one({'cve': cve})
        if doc:
            time = doc['time'].replace('.', '-')
        else:
            time = None
        if time:
            affected_versions = len(json.load(open('by_cve/'+cve+'/response.json')))
            span = 0
            df = pandas.read_csv('by_cve/'+cve+'/accumulative_by_day.csv')
            half_time = ''
            for date, colum in df.items():
                if '-' not in date:
                    continue
                if colum[len(colum)-1]<0.5:
                    half_time = date
                    break
            with open('rq1_statistics/half_life.csv', 'a') as f:
                life_time = (datetime.strptime('2023-01-01', '%Y-%m-%d') - datetime.strptime(time, '%Y-%m-%d')).days
                if half_time:
                    # print(half_time, time)
                    half_lifE = (datetime.strptime(half_time, '%Y-%m-%d') - datetime.strptime(time, '%Y-%m-%d')).days
                    # print(half_lifE)
                    csv.writer(f).writerow([cve, half_lifE/life_time, half_lifE, half_time, time, affected_versions])

                else:
                    half_lifE = 'inf'
                    csv.writer(f).writerow([cve, 1, half_lifE, half_time, time, affected_versions])


