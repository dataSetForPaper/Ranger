import csv
import os
import re
import subprocess

from config import revapi, japicmp_path, sembid_jar
from utils.miscellaneous import get_jar_path


def get_incompatible_apis(jar1, jar2):
    process = subprocess.Popen(
        [revapi, '-n', jar2, '-o', jar1,
         '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -Drevapi.reporter.text.minSeverity=BREAKING '],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()

    outs = out.decode("utf-8").split("\n\n")
    # print('Incompatible APIs:', len(outs))
    # print(revapi, '-n', jar2, '-o', jar1,
    #      '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -Drevapi.reporter.text.minSeverity=BREAKING ')
    incomp_apis = set()
    for o in outs:
        if 'old: <none>' in o:
            continue
        result = re.search('^(old:.*?)\n', o)
        if result and ' enum ' not in result.group(1):
            a = result.group(1)
            if 'method' in a:
                result = re.search("old: method .* (.*::.*\))", a)
            else:
                result = re.search("old: .* (.*::.*\))", a)
            if result:
                a = result.group(1).replace("::", ":").replace(" ", "")
                a = a.replace('===', '')
                # print(a)
                incomp_apis.add(a)
    # print(incomp_apis)
    return incomp_apis

def revapi_jar(jar1, jar2):
    ret = []
    # try:
    # print('/Users/lyuye/workspace/java-compatibility/otherTools/revapi-0.11.2/revapi.sh', '-n', jar2, '-o', jar1,
    #      '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING')
    # out = subprocess.run(f'/Users/lyuye/workspace/java-compatibility/otherTools/revapi-0.11.2/revapi.sh -n {jar2} -o {jar1} --extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING |grep -v "old: <none>"',capture_output=True)
    process = subprocess.Popen(
        [revapi, '-n', jar2, '-o', jar1,
         '--extensions=org.revapi:revapi-java:0.24.4,org.revapi:revapi-reporter-text:0.14.2 -D revapi.reporter.text.minSeverity=BREAKING'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    outs = out.decode("utf-8").split("\n\n")
    # print(len(outs))


    for o in outs:
        if 'old: <none>' in o:
            continue
        if 'BINARY: BREAKING' in o or 'SOURCE: BREAKING' in o:
            result = re.search('^(old:.*?)\n', o)
            if result and ' enum ' not in result.group(1):
                a = result.group(1)
                if 'method' in a:
                    result = re.search("old: method \S+ (.*\))", a)
                else:
                    result = re.search("old: \S+ (\S+)", a)
                if result:
                    a = result.group(1).replace("::", ":").replace(" ", "")
                    if ':' in a:

                        ret.append(a)
    # except Exception as e:
    #     print('[ERROR] revapi error', e)
    #     return ret
    return ret


def japicmp_jar(jar1, jar2):
    def parse_output(out):
        apis = set()
        old_clazz = ''
        clazz = ''
        for line in out.decode("utf-8").split('\n'):
            if line.startswith('****') or line.startswith('---'):
                clazz = line.split(' ')[-4]
                continue
            if clazz != '' and line.startswith('\t'):
                if 'REMOVED METHOD' in line:
                    elements = line.split(' ')
                    if '(' in elements[-1]:
                        apis.add(clazz + ':' + elements[-1])
                    else:
                        method = ''
                        elements.reverse()
                        for ele in elements:
                            method = ele + ' ' + method
                            if '(' in ele:
                                break
                        apis.add(clazz + ':' + method)
            else:
                old_clazz = clazz
        # print(apis)
        return apis
    process = subprocess.Popen(
        ['java', '-jar', japicmp_path, '-o' , jar1, '-n', jar2, '--ignore-missing-classes'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    return parse_output(out)


def get_incom_apis(c, ga, ver1, ver2):
    jar1 = get_jar_path(ga+'|'_ver1)
    jar2 = get_jar_path(ga+'|'_ver2)
    print('Calculating', ga, ver1, ver2, '\r', end='', flush=True)
    apis = list(japicmp_jar(jar1, jar2))
    if len(apis) == 0:
        apis = revapi_jar(jar1, jar2)
    # incom_coll.create_index('verp')
    return [api.replace(' ', '') for api in apis]

def get_semb_apis(ga, ver1, ver2, c):
    name = ga+'_'+ver1+'_'+ver2
    incom_coll = c['sembid_apis'][ga]
    if ver1 == ver2:
        return []
    doc = incom_coll.find_one({'verp': ver1 + '|' + ver2})
    jar1 = get_jar_path(ga + '|' + ver1)
    jar2 = get_jar_path(ga + '|' + ver2)
    if doc:
        return [api.replace(' ', '') for api in doc['apis']]
    else:
        print('Calculating Sembid', ga, ver1, ver2, '\r', end='', flush=True)
        apis = list(sembid(name, jar1, jar2))
        incom_coll.insert_one({'verp': ver1+'|'+ver2,
            'apis': apis
        }, bypass_document_validation=True)
        incom_coll.create_index('verp')
        return [api.replace(' ', '') for api in apis]


def sembid(name, jar1, jar2):
    def parse_output():
        ret = set()
        with open('results/'+ name+'_Incompatile.csv') as f:
            for l in f.readlines():
                api, method = l.split(' % ')
                ret.add(api)
        return ret

    print('java', '-jar', sembid_jar, name, jar1, jar2)
    process = subprocess.Popen(
        ['java', '-jar', sembid_jar, name, jar1, jar2],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.communicate()
    return parse_output()


def yuqiang_test():
    path = '/Users/lyuye/workspace/collegues/yuqiang/rocketmq/'
    files = list(os.listdir(path))
    for i in range(len(files)):
        if i + 1 != len(files):
            sembid(files[i].replace('.jar', '')+'_'+files[i+1].replace('.jar', '').split('-')[-1], path+files[i], path+files[i+1])

