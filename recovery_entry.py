import csv
import json
import os
import pickle
import concurrent.futures
import pymongo as pymongo
import requests
from pprint import pprint
from config import graph_api_port, graph_api_host, namelist, mongodb_host, mongodb_port, rem_res_path, project_path
from recover_range import recover_range_4_edge
from rq4_demo.export_range_results import export_results
from rq4_demo.iterative_accumulation import iterative_accumulation_gav, iterative_accumulation_ga
from rq4_demo.recover_log4j import get_dep_version
from utils.call_graphs import dynamic_cg
from utils.db_utils import get_all_versions
from utils.incom_api_calculation import yuqiang_test
from utils.miscellaneous import clear_placeHolder, get_libvers
from utils.mvn_utils import evaluate_original_for_benchmark



def dump_libvers():
    cwd = os.getcwd()
    libvers = set()
    for name in namelist:
        project_path = clear_placeHolder(project_path, name)
        edges, root = evaluate_original_for_benchmark(name, project_path, project_path[name]['original'])
        libvers = libvers.union(get_libvers(edges)[1])
        # break
    os.chdir(cwd)
    with open('deps.json', 'w') as f:
        f.write(json.dumps(list(libvers)))

def get_edges():
    edges = []
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    maven_deps = c['library-crawler']['maven_deps']
    with open('deps.json') as f, open('edges_demo.json', 'w') as fw:
        names = json.load(f)
        for name in names:
            doc = maven_deps.find_one({'parent': name.replace('|', ':')})
            if doc:
                for dep in doc['dependencies']:
                    edges.append([name, dep['dep'].replace(':', '|')])
        fw.write(json.dumps(edges))


count = 0


def each_edge(edge):
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)

    maven_range = c['library-crawler']['maven_range_only']
    maven_range.create_index('parent')
    global count
    count +=1
    src, dst, lvl = edge.split('%')
    lvl = int(lvl)
    print(count, 'Update', src, dst)
    try:
        range, callees = recover_range_4_edge(edge, lvl, c)



        maven_range.insert_one({
            'parent': src,
            'dep': dst,
            'range': range,
            'callees': list(callees),
            'depth': lvl
            })
    except Exception as e:
        print('General Exception', e)
        maven_range.insert_one({
            'parent': src,
            'dep': dst,
            'range': 'error',
            'callees': [],
            'depth': lvl
            })

    c.close()
    return



def read_visited(file_path):
    visited = set()
    with open(file_path) as f:
        for l in f.readlines():
            visited.add(l)
    return visited


def do_demo():
    count = 0
    visited = read_visited('visited.csv')
    with open('edges_demo.json') as f:
        edges = json.load(f)
        to_be_processed = []
        for e in edges:
            if ','.join(e) not in visited:
                to_be_processed.append(e)
        with concurrent.futures.ProcessPoolExecutor(3) as executor:
            executor.map(each_edge, to_be_processed)
            future_name = {executor.submit(each_edge, c, file): file for file in edges}
            for future in concurrent.futures.as_completed(future_name):
               pass


def get_visited(file):
    if os.path.exists(file):
        ret = []
        for each in csv.reader(open(file)):
            ret.append(each)
        return ret
    else:
        return []


# for the 4th work
def study_entry_of_tool(iter, c):
    log4j_depts = set()

    dependents = json.load(open(f'rq4_demo/response_{iter-1}_lvl_iter.json'))
    visited = set()
    other_depts = set()
    maven_range = c['library-crawler']['maven_range_only']
    for doc in maven_range.find():
        visited.add(doc['parent'])

    for dependent in dependents:
        if dependent['vendor']+'|'+dependent['library'] + '|' + dependent['version'] in visited:
            continue
        lvl = dependent['proList'][1]['propertyContent']
        date = dependent['proList'][0]['propertyContent']
        if lvl=='1' and date >='2021-12-09':
            log4j_version = get_dep_version('org.apache.logging.log4j', 'log4j-core', dependent['vendor']+'|'+dependent['library'] + '|' + dependent['version'], c)
            log4j_depts.add(dependent['vendor']+'|'+dependent['library'] + '|' + dependent['version']+'%'+'org.apache.logging.log4j|log4j-core|'+log4j_version+'%'+lvl)
        elif lvl == str(iter) and date >='2021-12-09':
            dep_gav = dependent['proList'][2]['propertyContent']
            other_depts.add(dependent['vendor']+'|'+dependent['library'] + '|' + dependent['version']+'%'+dep_gav+'%'+lvl)

    if iter == 1:
        print(len(log4j_depts))
        with concurrent.futures.ProcessPoolExecutor() as executor:
            executor.map(each_edge, log4j_depts)
    else:
        print(len(other_depts))
        with concurrent.futures.ProcessPoolExecutor() as executor:
            executor.map(each_edge, other_depts)



def tool_get_log4j_iteration(iter):
    if not os.path.exists(f'rq4_demo/response_{iter}_lvl_iter.json'):
        response = requests.post(f'http://{graph_api_host}:8090/log4jIter', json={'name': iter}).json()
        open(f'rq4_demo/response_{iter}_lvl_iter.json', 'w').write(json.dumps(response))
    iterative_accumulation_ga(iter)
    iterative_accumulation_gav(iter)


if __name__ =='__main__':
    c = pymongo.MongoClient(mongodb_host,
            port=mongodb_port)
    for i in range(0, 10):
        study_entry_of_tool(i, c)
        export_results(c, i)
        tool_get_log4j_iteration(i)


    c.close()


