import json

import requests

from config import graph_api_host


def get_log4j_blockers():
    response = requests.post(f'http://{graph_api_host}:8090/getLog4jBlockers', json={}).json()
    open('rq2_blocker/log4j_blockers.json', 'w').write(json.dumps(response))

