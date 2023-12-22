import logging
import os
import re
import subprocess
from collections import defaultdict

import pymongo

from config import mongodb_host, mongodb_port

def supplement_edges(c, deps, edges):
    maven_deps = c['library-crawler']['maven_deps']
    edge_dict = defaultdict(set)
    for edge in edges:
        dg, da, dv = edge[1].split('|')
        edge_dict[edge[0]].add(dg+'|'+da)
    dep_libs = {}
    for dep in deps:
        g, a, v = dep.split('|')
        dep_libs[g+'|'+a] = v
    for dep in deps:
        g,a,v = dep.split('|')
        doc = maven_deps.find_one({'parent': g+':'+a+':'+v})
        if doc:
            for dep_dep in doc['dependencies']:
                dg, da, dv = dep_dep['dep'].split(':')
                if dg+'|'+da not in edge_dict[dep] and dep_dep['dScope'] in {'compile', 'runtime'} \
                        and dep_dep['isoptional']=='false' and dg+'|'+da in dep_libs:
                    edges.append([dep, dg+'|'+da+'|'+dep_libs[dg+'|'+da]])
    return edges


def evaluate_original_for_benchmark(project, project_path, root_jar):
    connection = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    path = project_path[project]['original']
    main_jar = project_path[project]['jar']
    # get original deps
    cwd = os.getcwd()
    deps, edges, root = get_mvn_dep_tree(path)

    edges = supplement_edges(connection, deps, edges)
    return edges, root
    # visualize(edges, deps)
    os.chdir(cwd)

    # evaluation
    start_time = time()
    # root = next(iter(deps))
    old_cves = get_cves(deps)
    if check_reachabiliity:
        one_time_graph = read_local_call_graph(project, edges, root, root_jar)
    else:
        one_time_graph = set()
    print('Call graph took:', "%.2f" % (time() - start_time), 's')

    start_time2 = time()
    reachable_cves, unreachable_cves, unsure_cves = get_reachable_cves(one_time_graph, old_cves, connection)
    cvss = calculate_cvss(old_cves, connection)
    print('Reachable CVE took:', "%.2f" % (time() - start_time2), 's')
    save_benchmark_metrics(project, '0', reachable_cves, unreachable_cves, unsure_cves, 0, cvss, 0, 0, 0, 0, len(deps), connection)
    print('Pre-evaluation took:', "%.2f" % (time() - start_time), 's')
    connection.close()
    return edges, root

def get_mvn_dep_tree(path, large_scale=False):
    pairs = []
    deps = {}
    ids = {}
    os.chdir(path)
    logging.debug(path)
    if large_scale:
        with open(os.path.join(path, 'deptree.txt')) as f:
            output= f.read().split('\n')
    else:
        try:
            subprocess.check_output('mvn dependency:tree', stderr=subprocess.STDOUT, shell=True)
            output = subprocess.check_output('mvn dependency:tree -DoutputType=tgf', stderr=subprocess.STDOUT, shell=True).decode().split('\n')
        except Exception as e:
            raise RuntimeError('mvn dependency:tree error')
            logging.debug('mvn command error', e)
            return deps, pairs
    module_flag = True
    start = False

    edge_begin = False
    next_root = False
    root = ''
    for l in output:
        if not l.startswith('[INFO]'):
            continue
        res = re.search('--- maven-dependency-plugin:.*:tree \(default-cli\) @ (.+) ---', l)
        if res:
            # only parse one, stop before next starts
            if deps!={}:
                break
            module = res.group(1)
            module_flag = True
            start = True
            edge_begin = False
            next_root = True
            continue
        if next_root and start:
            root = l.split(' ')[-1]
            root = root.replace(':jar', '').replace(':pom', '').replace(':war', '').replace(':bundle', '')\
                .replace(':rar', '').replace(':eclipse-plugin', '').replace(':', '|')
            if 'maven-plugin-api' not in root:
                root = root.replace('|maven-plugin', '')
            if root.count('|') == 3:
                gavsp = root.split('|')
                g, a, v = gavsp[0], gavsp[1], gavsp[3]
                root = g+'|'+a+'|'+v
            next_root = False
            id = l.split(' ')[1]
            ids[id] = root
            continue
        if '#' in l:
            start = False
            edge_begin = True
            continue
        if (not start and not edge_begin) or not module_flag:
            continue
        if '-----------' in l:
            edge_begin = False
        if edge_begin and l.count(' ')>2:
            _, src, dst, compile = l.split(' ')
            if compile =='test':
                continue
            if src in ids and dst in ids:
                pairs.append([ids[src], ids[dst]])
            continue
        if l=='[INFO] ':
            module_flag = False
            continue
        if start:
            # if 'pom' in l:
            #     continue
            tmp = l.split(' ')
            id = tmp[1]
            latter = tmp[2]
            #_, id, latter = l.split(' ')
            gav = latter.split(':')
            scope = gav[-1]
            v = gav[-2]
            if scope =='test':
                continue
            if len(gav)<4:
                # logging.debug('Special: '+ gav)
                continue
            g = gav[0]
            a = gav[1]

            # if gav[3].startswith('jdk'):
            #     v = gav[4]
            # else:
            #     v = gav[3]
            jar = gav[2]
            # print(g, a ,v)
            ids[id] = g+'|'+a+'|'+v
            deps[g+'|'+a+'|'+v] = {'jar': jar, 'type': type}
    print('Number of deps:', len(deps))
    return deps, pairs, root