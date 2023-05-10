import csv
import json
import os
import re
import subprocess
from collections import defaultdict

from config import working_dir


def check_failed_pom(pom_path):
    with open(working_dir + 'soft_version_study/rq1_statistics/pom.xml', 'r') as pom_f, open(working_dir + 'soft_version_study/rq1_statistics/verify_fail.csv', 'r') as fail:
        content = pom_f.read()
        for line in csv.reader(fail):

            _, g,a,v = line
            if g=='g':
                continue
            substitute = content.replace('<groupId>io.scalecube</groupId>', f'<groupId>{g}</groupId>')
            substitute = substitute.replace('<artifactId>scalecube-benchmarks-log4j2</artifactId>',
                                            f'<artifactId>{a}</artifactId>')
            substitute = substitute.replace('<version>1.1.13</version>', f'<version>{v}</version>')

            with open(pom_path, 'w') as new_pom:
                new_pom.write(substitute)
            cwd = os.getcwd()
            os.chdir(pom_path.replace('/pom.xml', ''))
            result = subprocess.run('mvn dependency:tree', shell=True, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL).stdout.decode()
            with open(working_dir+'soft_version_study/rq1_statistics/failed_pom_mvn_dependencytree/'+g+'|'+a+'|'+v, 'w') as f:
                f.write(result)

            os.chdir(cwd)




def verify_pom(pom_path):
    def verify(dep, lvl, content):
        g = dep['vendor']
        a = dep['library']
        v = dep['version']
        if g + '|' + a + '|' + v in visited:
            return False
        substitute = content.replace('<groupId>io.scalecube</groupId>', f'<groupId>{g}</groupId>')
        substitute = substitute.replace('<artifactId>scalecube-benchmarks-log4j2</artifactId>',
                                        f'<artifactId>{a}</artifactId>')
        substitute = substitute.replace('<version>1.1.13</version>', f'<version>{v}</version>')

        with open(pom_path, 'w') as new_pom:
            new_pom.write(substitute)
        cwd = os.getcwd()
        os.chdir(pom_path.replace('/pom.xml', ''))
        result = subprocess.run('mvn dependency:tree', shell=True, check=False, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL).stdout.decode()
        if 'BUILD FAILURE' in result:
            with open(working_dir + 'rq1_statistics/verify_pom_black_list.csv', 'a') as f:
                csv.writer(f).writerow([lvl, g, a, v])
                return False
        else:
            success_flag = True
        re_res = re.search('org.apache.logging.log4j:log4j-core:\S+:(.*):', result)

        print(lvl, g, a, v)
        if re_res and f'{g}:{a}' in result:
            version = re_res.group(1)
            if version in log4j_versions:
                with open(working_dir + 'rq1_statistics/verify_success.csv', 'a') as verif:
                    writer = csv.writer(verif)
                    writer.writerow([lvl, g, a, v])
            else:
                with open(working_dir + 'rq1_statistics/verify_fail.csv', 'a') as fail:
                    fail_writer = csv.writer(fail)
                    fail_writer.writerow([lvl, g, a, v])
        else:
            with open(working_dir + 'rq1_statistics/verify_fail.csv', 'a') as fail:
                fail_writer = csv.writer(fail)
                fail_writer.writerow([lvl, g, a, v])
        os.chdir(cwd)
        return success_flag


    with open(working_dir+'response.json') as f:
        to_check = {}
        visited_vendor = set()
        for each in json.load(f):
            if each['vendor'] in visited_vendor:
                continue
            lvl = each['proList'][1]['propertyContent']
            if lvl =='1':
                continue
            if lvl not in to_check.keys():
                to_check[lvl] = []
            to_check[lvl].append(each)
            visited_vendor.add(each['vendor'])

    with open(working_dir+'rq1_statistics/verify_success.csv', 'r') as verif, open(working_dir+'rq1_statistics/verify_fail.csv', 'r') as fail, open(working_dir+'rq1_statistics/verify_pom_black_list.csv', 'r') as bl:
        visited = set()
        for line in csv.reader(verif):
            visited.add(f'{line[1]}|{line[2]}|{line[3]}')
        for line in csv.reader(fail):
            visited.add(f'{line[1]}|{line[2]}|{line[3]}')
        for line in csv.reader(bl):
            visited.add(f'{line[1]}|{line[2]}|{line[3]}')

    with open(working_dir+'rq1_statistics/pom.xml', 'r') as pom_f, open(working_dir+'rq1_statistics/verify_fail_last.csv') as last, open('response.csv') as resp:
        response = resp.read()
        content = pom_f.read()

        for lvl in to_check:
            checked_counter = 0
            for dep in to_check[lvl]:
                flag = verify(dep, lvl, content)
                if flag:
                    checked_counter+=1
