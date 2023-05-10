import csv
import json
import os
import re
from collections import defaultdict
import pandas as pd
import pymongo

def get_month(date, months):
    for m in months:
        if m in date:
            return m
    return None


def iterative_accumulation_ga(iter):

    total_by_month = defaultdict(set)
    count_by_month = {}
    release_dates = {}

    cve = 'CVE-2021-44228'
    months = ["2021-12", "2022-01", "2022-02", "2022-03", "2022-04", "2022-05", "2022-06", "2022-07", "2022-08",
              "2022-09", "2022-10", "2022-11", "2022-12", "2023-01", "2023-02", "2023-03", "2023-04"]
    if not os.path.exists(f'rq4_demo/response_{iter}_lvl_iter.json'):
        return
    # if os.path.exists('by_cve/'+folder+'/accumulative_by_day.csv'):
    #     continue
    with open(f'rq4_demo/response_{iter}_lvl_iter.json') as f, open(
            f'rq4_demo/response_patch.json') as pf:
        libvers = json.load(f)
        patch_libvers = json.load(pf)
        if True:
            unique_vers = defaultdict(set)
            gavs = defaultdict(list)
            time_vul = defaultdict(list)
            for libver in libvers:
                date = libver['proList'][0]['propertyContent']
                if date < '2021-12-09':
                    continue
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
            for libver in patch_libvers:
                date = libver['proList'][0]['propertyContent']
                if date < '2021-12-09':
                    continue
                lvl = libver['proList'][1]['propertyContent']
                unique_vers[libver['vendor'] + '|' + libver['library']].add(libver['version'])
                time_patch[date.split(' ')[0]].append(
                    libver['vendor'] + '|' + libver['library'] + '|' + libver['version'] + '|' + lvl)
            unfound_time = json.load(open('rq1_statistics/unfound_time.json'))
            asc_dates = list(time_vul.keys()) + list(time_patch.keys()) + list(unfound_time.keys())
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
                    if len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]) == 0:
                        df_by_day.at[lvl, each_date] = 0
                        patch_df_by_day.at[lvl, each_month] = 0
                        unfound_df_by_day.at[lvl, each_month] = 0
                        if each_month in months:
                            vul_df_by_month.at[lvl, each_month] = 0

                    else:
                        df_by_day.at[lvl, each_date] = len(per_lvl[lvl][0]) / (
                                len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]))
                        patch_df_by_day.at[lvl, each_date] = len(per_lvl[lvl][1]) / (
                                len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]))
                        unfound_df_by_day.at[lvl, each_date] = len(per_lvl[lvl][2]) / (
                                len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]))
                        if each_month in months:
                            vul_df_by_month.at[lvl, each_month] = len(per_lvl[lvl][0]) / (
                                    len(per_lvl[lvl][0]) + len(per_lvl[lvl][1]) + len(per_lvl[lvl][2]))
                if each_month in months:
                    vul_count_df_by_month.at['Total', each_month] = len(vul_gas)

                if len(vul_gas) + len(patched_gas) + len(unfound_gas) == 0:
                    df_by_day.at['Total', each_date] = 0
                    patch_df_by_day.at['Total', each_date] = 0
                    unfound_df_by_day.at['Total', each_date] = 0
                    if each_month in months:
                        vul_df_by_month.at['Total', each_month] = 0
                else:
                    df_by_day.at['Total', each_date] = len(vul_gas) / (
                                len(vul_gas) + len(patched_gas) + len(unfound_gas))
                    patch_df_by_day.at['Total', each_date] = len(patched_gas) / (
                            len(vul_gas) + len(patched_gas) + len(unfound_gas))
                    unfound_df_by_day.at['Total', each_date] = len(unfound_gas) / (
                            len(vul_gas) + len(patched_gas) + len(unfound_gas))
                    if each_month in months:
                        vul_df_by_month.at['Total', each_month] = len(vul_gas) / len(vul_gas) , len(patched_gas) , len(unfound_gas)

            vul_df_by_month.fillna(0)
            vul_count_df_by_month.fillna(0)
            vul_count_df_by_month.to_csv(f'rq4_demo/accumulative_count_by_month_{iter}_iter.csv')
            vul_df_by_month.to_csv(f'rq4_demo/accumulative_by_month_{iter}_iter.csv')


def iterative_accumulation_gav(iter):
    months = ["2021-12", "2022-01", "2022-02", "2022-03", "2022-04", "2022-05", "2022-06", "2022-07", "2022-08",
              "2022-09", "2022-10", "2022-11", "2022-12", "2023-01", "2023-02", "2023-03", "2023-04"]
    vul_count_df_by_month_all = pd.DataFrame(
        index=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
        columns=months)
    vul_df_by_month_all = pd.DataFrame(
        index=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10'],
        columns=months)
    for iter in range(0, 11):
        total_by_month = defaultdict(set)
        count_by_month = {}

        cve = 'CVE-2021-44228'

        if not os.path.exists(f'rq4_demo/response_{iter}_lvl_iter.json'):
            return
        with open(f'rq4_demo/response_{iter}_lvl_iter.json') as f, open(
                    f'rq4_demo/response_patch.json') as pf:
            libvers = json.load(f)
            if 'status' in libvers:
                print('error')
                return
            for libver in libvers:

                date = libver['proList'][0]['propertyContent']
                if date <'2021-12-09':
                    continue

                total_by_month[get_month(date, months)].add(libver['vendor'] + '|' + libver['library'] + '|' + libver['version'])

            vul_count_df_by_month = pd.DataFrame(
                index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                columns=months)
            vul_df_by_month = pd.DataFrame(
                index=['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', 'Total'],
                columns=months)
            previous_total = 0
            for each_month in months:
                previous_total+=len(total_by_month[each_month])
                vul_df_by_month.at['Total', each_month] = previous_total /raw_by_month[each_month]
                vul_count_df_by_month.at['Total', each_month] = previous_total#
                vul_count_df_by_month_all.at[str(iter), each_month] = previous_total
                vul_df_by_month_all.at[str(iter), each_month] = previous_total /raw_by_month[each_month]
            vul_count_df_by_month.to_csv(f'rq4_demo/accumulative_count_by_month_{iter}_iter.csv')
            vul_df_by_month.to_csv(f'rq4_demo/accumulative_by_month_{iter}_iter.csv')
        vul_count_df_by_month_all.to_csv(f'rq4_demo/accumulative_count_by_month_all.csv', quoting=csv.QUOTE_ALL)
        vul_df_by_month_all.to_csv(f'rq4_demo/accumulative_by_month_all.csv')
