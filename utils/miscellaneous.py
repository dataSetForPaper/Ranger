import json
import os
import subprocess

from config import m2_path, jar_path


def clear_placeHolder(project_path, project):
    sub_project = project.split('_')[-1]
    for key in project_path[project]:
        if 'PLACEHOLDER' in project_path[project][key]:
            project_path[project][key] = project_path[project][key].replace('PLACEHOLDER', sub_project)
    return project_path

def get_libvers(edges):
    ret = dict()
    ret2 = set()
    for edge in edges:
        # if edge[0] is None or edge[1] is None:
        #     d =2
        g, a, v = str(edge[0]).split('|')
        ret[g+'|'+a] = v
        ret2.add(str(edge[0]))
        g, a, v = str(edge[1]).split('|')
        ret[g + '|' + a] = v
        ret2.add(str(edge[1]))
    return ret, ret2

def get_path(g,a,v):
    download_path = '/home/jiahui/jar-engine/data/maven_2021'
    path2 = '/home/jiahui/jar-engine/data/maven_2020'
    path3 = '/home/jiahui/jar-engine/data/maven'
    path4 = '/home/jiahui/jar-engine/data/maven_2020_166'
    jar = os.path.join(download_path, g, a, v, a + '-' + v + '.jar')
    if not os.path.exists(jar):
        jar = os.path.join(path2, g, a, v, a + '-' + v + '.jar')
        if not os.path.exists(jar):
            jar = os.path.join(path3, g, a, v, a + '-' + v + '.jar')
            if not os.path.exists(jar):
                jar = os.path.join(path4, g, a, v, a + '-' + v + '.jar')
    return jar

def get_jar_path(gav1):
    g, a, v = gav1.split('|')
    path = get_path(g, a, v)
    if os.path.exists(path):
        jar1 = path
    elif os.path.exists(m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar'):
        jar1 = m2_path + '/' + g.replace('.', '/') + '/' + a + '/' + v + '/' + a + '-' + v + '.jar'
    elif os.path.exists(os.path.join(jar_path, a + '-' + v + '.jar')):
        jar1 = os.path.join(jar_path, a + '-' + v + '.jar')
    else:
        print('Downloading ' + gav1, '\r', end='', flush=True)
        download_one_jar(gav1)
        jar1 = os.path.join(jar_path, a + '-' + v + '.jar')
    return jar1

def download_one_jar(gav):
    # with open('download_failure_jar.json', 'r') as f:
    #     failures = set(json.load(f))
    #     if gav in failures:
    #         return
    group_id, artifact_id, version_name = gav.split('|')
    local_path = jar_path  # os.path.join(download_path, group_id, artifact_id, version_name)
    os.makedirs(local_path, exist_ok=True)

    if os.path.exists(os.path.join(local_path, artifact_id + '-' + version_name + '.jar')):
        return
    try:
        # logging.debug(os.path.join(local_path, artifact_id + '-' + version_name + '.jar'))
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
        # with open('download_failure_jar.json', 'w') as f:
        #     failures.add(gav)
        #     f.write(json.dumps(list(failures)))
