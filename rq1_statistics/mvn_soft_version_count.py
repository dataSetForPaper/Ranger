import pymongo

from config import mongodb_host, mongodb_port


def count_soft_verisons():
    c = pymongo.MongoClient(mongodb_host,
                            port=mongodb_port)
    maven_deps = c['library-crawler']['maven_deps']
    counter = 0
    all = 0
    for doc in maven_deps.find():
        print(counter , '\r', end='', flush=True)
        for dep in doc['dependencies']:
            all+=1
            version = dep['dep'].split(':')[-1]
            if ',' not in version and '(' not in version and ')' not in version and '[' not in version and ']' not in version:
               counter +=1
    print(counter)
    print(all)
