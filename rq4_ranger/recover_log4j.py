import json
import os
import pymongo
import signal
from collections import defaultdict
import subprocess
import csv
from config import m2_path, mongodb_port, mongodb_host, jar_path, working_dir

def recover_4_log4j():
    ret = set()
    c = pymongo.MongoClient(mongodb_host,
            port=mongodb_port)
    callgraph_db_direct = c['call_graphs_direct']
    callgraph_db_all = c['call_graphs_all']
    dependents = json.load(open('response.json'))
    print(len(dependents))
    for dependent in dependents:
        lvl = dependent['proList'][1]['propertyContent']
        date = dependent['proList'][0]['propertyContent']
        if lvl=='1' and date >='2021-12-09':
            ret.add(dependent['vendor']+'|'+dependent['library'] + '|' + dependent['version'])

    print(len(ret))
    for each in ret:
        print(each)
        callers = generate_callgraph(each, callgraph_db_direct, callgraph_db_all)
        dep_ver = get_dep_version('org.apache.logging.log4j', 'log4j-core', each, c)
        if dep_ver:
            callees = get_callees('org.apache.logging.log4j|log4j-core|'+dep_ver, callers, callgraph_db_direct, callgraph_db_all)

def get_dep_version(dep_g, dep_a, dept_gav, c):
    maven_deps = c['library-crawler']['maven_deps']
    doc = maven_deps.find_one({'parent': dept_gav.replace('|', ':')})
    if doc:
        for dep in doc['dependencies']:
            if dep_g+':'+dep_a in dep['dep']:
                return dep['dep'].replace(dep_g+':'+dep_a+':', '')

    return None

def download_one_jar(gav):
    group_id, artifact_id, version_name = gav.split('|')
    local_path = jar_path  # os.path.join(download_path, group_id, artifact_id, version_name)
    os.makedirs(local_path, exist_ok=True)

    if os.path.exists(os.path.join(local_path, artifact_id + '-' + version_name + '.jar')):
        return
    try:
        result = subprocess.check_output(f'mvn dependency:get \
                    -DgroupId=%s \
                    -DartifactId=%s \
                    -Dversion=%s \
                    -Dtransitive=false \
                    -Ddest={local_path} \
                    -DremoteRepositories=https://repo1.maven.org/maven2/ \
                    -Dpackaging=jar' % (group_id,
                                        artifact_id,
                                        version_name), shell=True)
    except:
        pass


def generate_csv(jar, main_class='', regeneration=False, order=''):
    error = False
    try:
        if not os.path.exists(working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv')) or os.path.getsize(working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv'))==0 or regeneration:
            # os.system('java -jar '+ working_dir+'libs/sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class)
            output = subprocess.check_output('java -jar '+ working_dir+'libs/sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class, stderr=subprocess.STDOUT,
                                         shell=True).decode()
            print(output)
    except Exception as exc:
        print(exc)
        error = True
    return working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv').replace('.war', '.csv'), working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '_NameList.csv').replace('.ar', '_NameList.csv'), error#, 'graph/'+jar.split('/')[-1].replace('.jar', '_api.csv')


def generate_callgraph(dep, callgraph_db_direct, callgraph_db_all):
    def handler(signum, frame):
        raise Exception("Timeout")
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(600)
    deps = dict()
    try:
        g, a, v = dep.split('|')
        coll = callgraph_db_all[g+'|'+a]
        coll.create_index('version')
        docs = coll.find_one({'version': v})

        regen = False
        if docs:
            return

        else:
            regen = True
        if regen:
            if os.path.exists(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar'):
                edge_csv, namelist_csv, error = generate_csv(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar')
            elif os.path.exists(os.path.join(jar_path, a+'-'+v+'.jar')):
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a+'-'+v+'.jar'))
            else:
                download_one_jar(dep)
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))

            direct_calls = defaultdict(list)
            edges = []
            for line in csv.reader(open(edge_csv)):
                edges.append(line)
                direct_calls[line[0]].append(line[1])
            callgraph_db_direct[g+'|'+a].update_many({
                'version': v},{'$set':{
                'deps': direct_calls,
                'error': error
            }},upsert=True)
            indirect_calls = dict()
            for key in direct_calls:
                callees = set()
                next = {key}
                visited = set()
                while(len(next)>0):
                    tmp = {*next}
                    next = set()
                    for caller in tmp:
                        if caller not in visited:
                            next = next.union(direct_calls.get(caller,{}))
                            callees = callees.union(direct_calls.get(caller,{}))
                            visited.add(caller)
                indirect_calls[key] = list(callees)

            try:
                callgraph_db_all[g+'|'+a].update_many({
                'version': v},{'$set':{
                'deps': indirect_calls,
                'error': error
            }},upsert=True)
            except:
                batch = {}
                try:
                    for key in indirect_calls:
                        batch[key] = indirect_calls[key]
                        if len(batch.keys()) == 10:
                            callgraph_db_all[g + '|' + a].update_many({
                                'version': v},{'$set':{
                                'deps': batch,
                                'error': error
                            }},upsert=True)
                            batch = {}
                    callgraph_db_all[g + '|' + a].update_many({
                                'version': v},{'$set':{
                                'deps': batch,
                                'error': error
                            }},upsert=True)
                    callgraph_db_all[g + '|' + a].create_index('version')
                except:
                    for key in indirect_calls:
                        callgraph_db_all[g + '|' + a].update_many({
                            'version': v}, {'$set': {
                            'deps': {key: indirect_calls[key]},
                            'error': error
                        }}, upsert=True)
                callgraph_db_all[g + '|' + a].create_index('version')


        signal.alarm(0)
        return set(indirect_calls.values())
    except Exception as exc:
        print('[ERROR] Callgraph timeout', exc)
        docs = coll.find({'version': v})
        if not docs:
            callgraph_db_all[g + '|' + a].insert_one({
                'version': v,
                'deps': {},
                'timeout': True
            })
        signal.alarm(0)
        return set()
    signal.alarm(0)
    return set()


def get_callees(dep, parent_callers, callgraph_db_direct, callgraph_db_all):
    def handler(signum, frame):
        raise Exception("Timeout")
    if len(parent_callers)==0:
        return set()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(600)
    deps = dict()
    ret = set()
    try:
        g,a,v = dep.split('|')
        coll = callgraph_db_all[g+'|'+a]
        coll.create_index('version')
        docs = coll.find_one({'version': v})
        regen = False
        if docs:
            print('Retrieving from mongo:', dep, '\r', end='',flush=True)
            docs = coll.find({'version': v})
            deps = dict()
            for doc in docs:
                deps = {**deps, **doc['deps']}
            if len(deps) ==0 and doc.get('timeout', False)==False and doc.get('error', False)==False:
                regen =True
        else:
            regen = True
        if regen:
            if os.path.exists(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar'):
                edge_csv, namelist_csv, error = generate_csv(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar')
            elif os.path.exists(os.path.join(jar_path, a+'-'+v+'.jar')):
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a+'-'+v+'.jar'))
            else:
                download_one_jar(dep)
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))

            direct_calls = defaultdict(list)
            edges = []
            for line in csv.reader(open(edge_csv)):
                edges.append(line)
                direct_calls[line[0]].append(line[1])
            callgraph_db_direct[g+'|'+a].update_many({
                'version': v},{'$set':{
                'deps': direct_calls,
                'error': error
            }},upsert=True)
            indirect_calls = dict()
            for key in direct_calls:
                callees = set()
                next = {key}
                visited = set()
                while(len(next)>0):
                    tmp = {*next}
                    next = set()
                    for caller in tmp:
                        if caller not in visited:
                            next = next.union(direct_calls.get(caller,{}))
                            callees = callees.union(direct_calls.get(caller,{}))
                            visited.add(caller)
                indirect_calls[key] = list(callees)

            try:
                callgraph_db_all[g+'|'+a].update_many({
                'version': v},{'$set':{
                'deps': indirect_calls,
                'error': error
            }},upsert=True)
            except:
                batch = {}
                try:
                    for key in indirect_calls:
                        batch[key] = indirect_calls[key]
                        if len(batch.keys()) == 10:
                            callgraph_db_all[g + '|' + a].update_many({
                                'version': v},{'$set':{
                                'deps': batch,
                                'error': error
                            }},upsert=True)
                            batch = {}
                    callgraph_db_all[g + '|' + a].update_many({
                                'version': v},{'$set':{
                                'deps': batch,
                                'error': error
                            }},upsert=True)
                    callgraph_db_all[g + '|' + a].create_index('version')
                except:
                    for key in indirect_calls:
                        callgraph_db_all[g + '|' + a].update_many({
                            'version': v}, {'$set': {
                            'deps': {key: indirect_calls[key]},
                            'error': error
                        }}, upsert=True)
                callgraph_db_all[g + '|' + a].create_index('version')
            deps = indirect_calls


        for each in parent_callers:
            ret = ret.union(deps.get(each, set()))
        signal.alarm(0)
        return ret
    except Exception as exc:
        print('[ERROR] Callgraph timeout', exc)
        docs = coll.find({'version': v})
        if not docs:
            callgraph_db_all[g + '|' + a].insert_one({
                'version': v,
                'deps': {},
                'timeout': True
            })
        signal.alarm(0)
        return ret
    signal.alarm(0)
    return set()

