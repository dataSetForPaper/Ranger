import json
import subprocess

import requests
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import pymongo
from datetime import datetime

from config import mongodb_host, mongodb_port, semver_host, semver_port

Host = '119.8.168.13'
Port = 5432
DB = 'cvetriage'
User = 'cvetriage'
Password = ';Vj93rquRi8aTB'

c = pymongo.MongoClient(mongodb_host,
                        port=mongodb_port)
maven_deps = c['library-crawler']['maven_deps']
maven = c['library-crawler']['maven']
def update_cvss(collection, cvss_col):
    timestamp = collection.find_one({'key': 'timestamp'})['timestamp']
    cvss_col.create_index('cve')
    Base = automap_base()
    # Create engine, session
    engine = create_engine(f'postgresql+psycopg2://{User}:{Password}@{Host}:5432/{DB}',
                          client_encoding='utf-8')
    session = Session(engine)
    # Reflect the tables
    Base.prepare(engine, reflect=True)
    # Mapped classes are now created with names by default
    # matching that of the table name.
    si = Base.classes.scantist_securityissue
    cvss = Base.classes.scantist_cvssv3
    # TODO: get only specific columns
    vul_query_result = (session
                              .query(cvss, si)
                              .filter(si.id==cvss.vulnerability_id,cvss.created>timestamp)
                              .with_entities(si.public_id, cvss.score, cvss.created))
    count =0
    print('Populating')
    for each in vul_query_result:
        print(count)
        cvss_col.update_one({'cve': each[0]}, {'$set':{'cve':each[0], 'cvss': each[1], 'created': each[2]}}, upsert=True)
        count +=1

    collection.update_one({'key':'timestamp'}, {'$set':{'timestamp': datetime.now(tz=None)}})
def get_cvss(cves, cvss_col):
    ret = {}
    for cve in cves:
        doc = cvss_col.find_one({'cve': cve})
        if doc:
            ret[cve] = doc['cvss']
        else:
            ret[cve] = 0
    return ret

def generate_dep_now(gav):
    gav = gav.replace('|', ':')
    open('tmp/gavs.json', 'w').write(json.dumps([gav]))
    subprocess.call(['java', '-jar', './utils/dependency/maven-resolver-provider-3.6.3-jar-with-dependencies.jar', 'tmp/gavs.json'])



def dictize_deps(doc):
    ret = {}
    for dep in doc['dependencies']:
        if dep['dScope']!= 'compile' and dep['dScope']!='runtime':
            continue
        if dep['isoptional']== "true":
            continue
        g,a,v = dep['dep'].split(':')
        ret[g+'|'+a] = v
    return ret

def get_dep_tree(root):
    body = []
    unfound = []
    gav = root
    g, a, v = gav.split('|')
    # if not maven.find_one({'group': g, 'artifact': a, 'version': v}):
    #     unfound.append(gav)
    #     continue
    body.append({
        "name": a,
        "vendor": g,
        "version": v,
        "platform": "maven"
    })
    response = requests.post(f'http://{graph_api_host}:{graph_api_port}/allDependencies', json=body)
    if response.status_code == 200:
        try:
            return response.json()
        except:
            return {}
    return {}

def get_all_versions(ga, maven):
    g, a = ga.split('|')
    ret = []
    for doc in maven.find({'group': g, 'artifact': a}):
        ret.append(doc['version'])
    if '' in ret:
        ret.remove('')
    return ret

def _sort(versionlist, session=None):
    versionlist = '|'.join(versionlist)
    if session == None:
        session = requests.session()
    res = session.post('http://' + semver_host + f':{semver_port}/sort', data={'versionlist': versionlist})

    res.raise_for_status()
    res = res.content.decode().split('|')
    res = [p.replace('\"', '').replace(' ', '+') for p in res]
    if res ==['']:
        res = []
    return res

if __name__ == '__main__':
    c = pymongo.MongoClient('119.8.190.75',
                            port=8635,
                            username='rwuser',
                            password='Sc@ntist123',
                            authSource='admin',
                            authMechanism='SCRAM-SHA-256')
    collection = c['remediation']['cvss_timestamp']
    update_cvss(collection, c['remediation']['cvss'])