import csv
import json
import os
import re
import signal
import subprocess
from collections import defaultdict

from config import working_dir, m2_path, jar_path, graph_dir
from utils.miscellaneous import download_one_jar


# def read_local_call_graph(project_name, edges, root, jar):
#     project_name = project_name.replace('/', '_')
#     if os.path.exists(working_dir+'graphs/'+project_name+'.json') and os.path.getsize(working_dir+'graphs/'+project_name+'.json')!=0:
#         return json.load(open(working_dir+'graphs/'+project_name+'.json'))
#     else:
#         call_graph = create_call_graph_dict(edges, root, jar)
#         open(working_dir+'graphs/'+project_name+'.json', 'w').write(json.dumps(call_graph))
#         return call_graph


def get_root_callees(root_jar):
    if not os.path.exists(root_jar):
        print('[WARNING] Root jar not exits:', root_jar)
        raise Exception('jar not exists '+ root_jar)
        return set()
        # raise FileNotFoundError('Root jar not exits:', root_jar)
    edge_csv, namelist_csv, error = generate_csv(root_jar)
    callees = set()
    with open(edge_csv) as f:
        for i in csv.reader(f):
            callees.add(i[1])
    return callees

def get_callees(dep, parent_callers, c=None):
    if c!=None:
        callgraph_db_direct = c['call_graphs_direct']
        callgraph_db_all = c['call_graphs_all']
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

            # if 'druid' in dep:
            #     print('')
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
                    'deps': [],
                    'timeout': True
                })
            signal.alarm(0)
            return ret
        signal.alarm(0)
        return set()
    else:
        g,a,v = dep.split('|')
        deps = dict()
        ret = set()
        if os.path.exists(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar'):
            edge_csv, namelist_csv, error = generate_csv(m2_path+'/'+g.replace('.', '/')+'/'+a +'/'+v+'/'+a +'-' + v + '.jar')
        elif os.path.exists(os.path.join(jar_path, a+'-'+v+'.jar')):
            edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a+'-'+v+'.jar'))
        else:
            download_one_jar(dep)
            edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))
        direct_calls = defaultdict(list)
        for line in csv.reader(open(edge_csv)):
            direct_calls[line[0]].append(line[1])
        
        for each in parent_callers:
            ret = ret.union(deps.get(each, set()))

        return ret

def populate_cg_db(dep, c):
    callgraph_db_direct = c['call_graphs_direct']
    callgraph_db_all = c['call_graphs_all']

    def handler(signum, frame):
        raise Exception("Timeout")

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(600)
    try:
        g, a, v = dep.split('|')
        coll = callgraph_db_all[g + '|' + a]
        coll.create_index('version')
        docs = coll.find_one({'version': v})

        if not docs:
            if os.path.exists(m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar'):
                edge_csv, namelist_csv, error = generate_csv(
                    m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar')
            elif os.path.exists(os.path.join(jar_path, a + '-' + v + '.jar')):
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))
            else:
                download_one_jar(dep)
                edge_csv, namelist_csv, error = generate_csv(os.path.join(jar_path, a + '-' + v + '.jar'))

            direct_calls = defaultdict(list)
            edges = []
            for line in csv.reader(open(edge_csv)):
                edges.append(line)
                direct_calls[line[0]].append(line[1])
            callgraph_db_direct[g + '|' + a].update_many({
                'version': v}, {'$set': {
                'deps': direct_calls,
                'error': error
            }}, upsert=True)
            indirect_calls = dict()
            for key in direct_calls:
                callees = set()
                next = {key}
                visited = set()
                while (len(next) > 0):
                    tmp = {*next}
                    next = set()
                    for caller in tmp:
                        if caller not in visited:
                            next = next.union(direct_calls.get(caller, {}))
                            callees = callees.union(direct_calls.get(caller, {}))
                            visited.add(caller)
                indirect_calls[key] = list(callees)

            try:
                callgraph_db_all[g + '|' + a].update_many({
                    'version': v}, {'$set': {
                    'deps': indirect_calls,
                    'error': error
                }}, upsert=True)
            except:
                batch = {}
                try:
                    for key in indirect_calls:
                        batch[key] = indirect_calls[key]
                        if len(batch.keys()) == 10:
                            callgraph_db_all[g + '|' + a].update_many({
                                'version': v}, {'$set': {
                                'deps': batch,
                                'error': error
                            }}, upsert=True)
                            batch = {}
                    callgraph_db_all[g + '|' + a].update_many({
                        'version': v}, {'$set': {
                        'deps': batch,
                        'error': error
                    }}, upsert=True)
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
    except Exception as exc:
        print('[ERROR] Callgraph timeout', exc)
        docs = coll.find({'version': v})
        if not docs:
            callgraph_db_all[g + '|' + a].insert_one({
                'version': v,
                'deps': [],
                'timeout': True
            })
        signal.alarm(0)


def dynamic_cg(repo, gav, dep_ga,  c):
    coll = c['dynamic_cg']['edge_based']
    doc = coll.find_one({'edge': gav+'----'+dep_ga})
    dep_g = dep_ga.split('|')[0]
    if False:#doc:
        return doc['callees']
    else:
        cwd = os.getcwd()
        os.chdir(repo)
        print(f'java -javaagent:/Users/lyuye/workspace/maven-range-recovery/utils/java-callgraph/target/javacg-0.1-SNAPSHOT-dycg-agent.jar="incl=org.slf4j.impl.*" -classpath /usr/local/Cellar/maven/3.8.2/libexec/boot/plexus-classworlds-2.6.0.jar:/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/jre/lib/rt.jar:/Users/lyuye/workspace/maven-range-recovery/utils/java-callgraph/target/javacg-0.1-SNAPSHOT-dycg-agent.jar -Dclassworlds.conf=/usr/local/Cellar/maven/3.8.2/libexec/bin/m2.conf -Dmaven.home=/usr/local/Cellar/maven/3.8.2/libexec -Dmaven.multiModuleProjectDirectory={repo} org.codehaus.plexus.classworlds.launcher.Launcher test')
        output = subprocess.check_output(
            f'/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/bin/java -javaagent:/Users/lyuye/workspace/maven-range-recovery/utils/java-callgraph/target/javacg-0.1-SNAPSHOT-dycg-agent.jar="incl={dep_g}.*;" -classpath /usr/local/Cellar/maven/3.8.2/libexec/boot/plexus-classworlds-2.6.0.jar:/Library/Java/JavaVirtualMachines/adoptopenjdk-8.jdk/Contents/Home/jre/lib/rt.jar:/Users/lyuye/workspace/maven-range-recovery/utils/java-callgraph/target/javacg-0.1-SNAPSHOT-dycg-agent.jar -Dclassworlds.conf=/usr/local/Cellar/maven/3.8.2/libexec/bin/m2.conf -Dmaven.home=/usr/local/Cellar/maven/3.8.2/libexec -Dmaven.multiModuleProjectDirectory={repo} org.codehaus.plexus.classworlds.launcher.Launcher test', stderr=subprocess.STDOUT,
            shell=True).decode()
        ret = []

        with open('calltrace.txt') as f:
            for line in f.readlines():
                l = re.sub('.*\]', '', line).split('=')[0]

                ret.append(l)
        ret = list(set(ret))
        print(ret)
        os.chdir(cwd)
        coll.insert_one({
            'edge': gav+'----'+dep_ga,
            'callees': ret
            })
        return ret

def generate_csv(jar, main_class='com.macro.mall.MallAdminApplication', regeneration=False, order=''):
    # print(os.path.getsize('graph/'+jar.split('/')[-1].replace('.jar', '.csv')))
    os.makedirs(working_dir+'graph/', exist_ok=True)
    cwd = os.getcwd()
    # os.chdir()
    error = False
    try:
        if not os.path.exists(working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv')) or os.path.getsize(working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv'))==0 or regeneration:
            # os.system('java -jar '+ working_dir+'libs/sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class)
            output = subprocess.check_output('java -jar '+ working_dir+'libs/callgraph/sootTest-1.0-SNAPSHOT-jar-with-dependencies.jar '+jar+' '+order+jar.split('/')[-1].replace('.jar', '')+' '+main_class, stderr=subprocess.STDOUT,
                                         shell=True).decode()
            print(output)

    except Exception as exc:
        print(exc)
        error = True
    os.chdir(cwd)
    return working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '.csv').replace('.war', '.csv'), working_dir+'graph/'+order+jar.split('/')[-1].replace('.jar', '_NameList.csv').replace('.ar', '_NameList.csv'), error#, 'graph/'+jar.split('/')[-1].replace('.jar', '_api.csv')
