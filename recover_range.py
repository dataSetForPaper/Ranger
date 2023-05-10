import requests

from config import graph_api_host
from utils.call_graphs import get_root_callees, get_callees
from utils.db_utils import get_all_versions, _sort
from utils.incom_api_calculation import get_incom_apis, get_semb_apis
from utils.miscellaneous import get_jar_path


def get_synb_range(dst, callees, c):
    dg, da, dv = dst.split('|')
    dga = dg+'|'+da
    maven = c['library-crawler']['maven']
    all_dep_versions = _sort(get_all_versions(dga, maven))
    # range is  a list of available versions
    range = []
    if len(callees) == 0:
        print('[WARNING]', 'callees are empty', dst)
        return all_dep_versions
    if dv in all_dep_versions:
        upper = all_dep_versions[all_dep_versions.index(dv):]
        for ver in upper:
            apis = set(get_incom_apis(c, dga, dv, ver))
            if len(apis.intersection(callees)) > 0 or (upper.index(ver) == len(upper)-1 and len(apis.intersection(callees))==0):
                range.extend(upper[:upper.index(ver)])
                break
        lower = all_dep_versions[:all_dep_versions.index(dv)]
        lower.reverse()
        for ver in lower:
            apis = set(get_incom_apis(c, dga, dv, ver))
            if len(apis.intersection(callees)) > 0 or (lower.index(ver) == len(lower)-1 and len(apis.intersection(callees))==0):
                range.extend(lower[:lower.index(ver)])
                break
    else:
        for ver in all_dep_versions:
            apis = set(get_incom_apis(c, dga, dv, ver))
            if len(apis.intersection(callees))==0:
                range.append(ver)
    range = _sort(range)
    return range

def get_semb_range(dst, synb_range, callees, c):
    dg, da, dv = dst.split('|')
    dga = dg+'|'+da
    all_dep_versions = synb_range
    # range is  a list of available versions
    range = []
    if len(callees) == 0:
        print('[WARNING]', 'callees are empty', dst)
        return synb_range
    if dv in all_dep_versions:
        upper = all_dep_versions[all_dep_versions.index(dv):]
        for ver in upper:
            apis = set(get_semb_apis(dga, dv, ver, c))
            if len(apis.intersection(callees)) > 0 or (upper.index(ver) == len(upper)-1 and len(apis.intersection(callees))==0):
                range.extend(upper[:upper.index(ver)])
                break
        lower = all_dep_versions[:all_dep_versions.index(dv)]
        lower.reverse()
        for ver in lower:
            apis = set(get_semb_apis(dga, dv, ver, c))
            if len(apis.intersection(callees)) > 0 or (lower.index(ver) == len(lower)-1 and len(apis.intersection(callees))==0):
                range.extend(lower[:lower.index(ver)])
                break
    else:
        print('[ERROR]', dv, 'is not in db', dst)
        for ver in all_dep_versions:
            apis = set(get_semb_apis(dga, dv, ver, c))
            if len(apis.intersection(callees))==0:
                range.append(ver)
    range = _sort(range)
    return range

def get_target_clean_ver(edge, iter=1, affected_gavs=[], c=None):
    src, dst, lvl = edge.split('%')
    vulnerable_log4j_versions = ["2.0.1", "2.1", "2.0.2", "2.3", "2.2", "2.4", "2.4.1", "2.5", "2.6", "2.6.1", "2.6.2", "2.7", "2.8", "2.8.1", "2.8.2", "2.9.0", "2.10.0", "2.11.0", "2.11.1", "2.11.2", "2.12.0", "2.12.1", "2.13.0", "2.13.1", "2.13.2", "2.13.3", "2.14.0", "2.14.1"]
    clean_log4j_versions = ['2.3.1', '2.12.2', '2.15.0']
    if 'org.apache.logging.log4j|log4j-core|' in dst:
        log4j_ver = dst.replace('org.apache.logging.log4j|log4j-core|', '')
        minor = log4j_ver.split('.')[1]

        if int(minor)<=3:
            return clean_log4j_versions[0]
        elif int(minor)<=12:
            return clean_log4j_versions[1]
        elif int(minor)<=15:
            return clean_log4j_versions[2]
    else:
        g,a,v = dst.split('|')
        response = requests.post(f'http://{graph_api_host}:8090/findVersionUnaffectedByLog4j', json={'name': a, 'vendor':g, 'version':v}).text

        if '404' not in response and response != '':
            return response
        else:
            return ''



def recover_range_4_edge(edge, iter, c, affected_gavs=[]):
    src, dst, lvl = edge.split('%')
    g, a, v = src.split('|')
    dg, da, dv = dst.split('|')
    dga = dg+'|'+da
    src_jar = get_jar_path(src)
    callers = get_root_callees(src_jar)
    callees = get_callees(dst, callers, c)

    target_ver = get_target_clean_ver(edge, iter)
    if target_ver=='':
        return "No suitable version", callees
    if len(callees) == 0:
        return '['+dv+','+target_ver+']', callees
    incom_apis = set(get_incom_apis(c, dga, dv, target_ver))
    if len(incom_apis.intersection(callees)) > 0:
        return None, callees
    else:
        return '['+dv+','+target_ver+']', callees



