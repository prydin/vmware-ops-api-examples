import argparse
import ssl
import json
import sys
import yaml
import time
from urllib.error import URLError
from urllib import request

PAGESIZE = 1000

url_base = ""

headers = {"Accept": "application/json", "Content-Type": "application/json" }

ssl_context = ssl.create_default_context()

def login(host, username, password, auth_source=None):
    # Validate password. This will return a token that can be used
    # throughout the session.
    global url_base
    url_base = "https://" + host + "/suite-api"
    cred_payload = {"username": username, "password": password}
    if auth_source:
        cred_payload["authSource"] = auth_source
    credentials = json.dumps(cred_payload)

    rq = request.Request(url=url_base + "/api/auth/token/acquire", data=credentials.encode("UTF-8"), headers=headers)
    response = request.urlopen(url=rq, context=ssl_context)

    if response.status != 200:
        print(str(response.status) + " " + response.read().decode())
        exit(1)
    json_data = json.loads(response.read().decode())
    token = json_data["token"]
    headers["Authorization"] = "vRealizeOpsToken " + token

def get(uri):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context)
    if response.status != 200:
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode("UTF-8")))
    return json.loads(response.read().decode("UTF-8"))

def get_streaming(uri, out):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context)
    if response.status != 200:
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode("UTF-8")))
    while True:
        content = response.read(10000)
        if not content:
            break
        out.write(content)

def post(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    if response.status not in range(200,299):
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode))
    content = response.read().decode("UTF-8")
    if len(content) == 0:
        return None
    return json.loads(content)

def put(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers, method="PUT")
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    if response.status not in range(200,299):
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode))
    return json.loads(response.read().decode("UTF-8"))

def get_resources_by_name(adapter_kind, resource_kind, name, page):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
    }
    if name:
        payload["name"] = name
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response["resourceList"]

def get_metrics(resource_ids, metric_keys, start_time):
    payload = {
        "resourceId": resource_ids,
        "statKey": metric_keys,
        "begin": start_time,
        "rollUpType": "MAX",
        "intervalType": "MINUTES",
        "intervalQuantifier": 5
    }
    return post("/api/resources/stats/query", payload)


# MAIN PROGRAM

# Parse command arguments
parser = argparse.ArgumentParser(
    prog='slo-calc',
    description='Calculates SLO attainment based on a metric limit',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument("-c", "--config", required=True)
parser.add_argument('-U', '--unsafe', required=False, action="store_true")

args = parser.parse_args()

# Load configuration
with open(args.config) as f:
    config = yaml.safe_load(f)

# Create a client connection
if args.unsafe:
    ssl_context = ssl._create_unverified_context()
try:
    login(args.host, args.user, args.password, args.authsource)
except URLError as e:
    if "certificate" in str(e):
        sys.stderr.write("The server appears to have a self-signed certificate. Override by adding the --unsafe option (not recommended in production)\n")
        sys.exit(1)
    else:
        raise e

for slo in config["slo_list"]:
    metric_name = slo["metric"]
    start_time = int(time.time() - 86400 * 30) * 1000
    op_lt = slo["operator"].upper() == "LT"
    threshold = int(slo["threshold"])
    resource_type = slo["resourceType"]
    slo_name = slo["name"]
    # Discover VMs in chunks of 1000
    page = 0
    while True:
        # Get the resources. We don't care if the machine is powered on.
        resources = get_resources_by_name("VMWARE", resource_type, None, page)
        if not resources or len(resources) == 0:
            break
        page += 1

        # Build a dictionary of resource ids mapped to names.
        ids_to_names = {}
        for r in resources:
            ids_to_names[r["identifier"]] = r["resourceKey"]["name"]

        # Collect metrics
        metrics = get_metrics(list(ids_to_names.keys()), [metric_name], start_time)

        # Loop through the metrics
        for metric_chunk in metrics["values"]:
            breaches = 0
            id = metric_chunk["resourceId"]
            name = ids_to_names[id]
            metric_list = metric_chunk["stat-list"]["stat"]
            for metric in metric_list:
                timestamps = metric["timestamps"]
                data = metric["data"]
                statkey = metric["statKey"]
                first_ts = timestamps[0]
                last_ts = timestamps[len(timestamps)-1]
                timespan = last_ts - first_ts
                for i, ts in enumerate(timestamps):
                    if (op_lt and data[i] < threshold) or (not op_lt and data[i] > threshold):
                        breaches += 1
                print(f"{name},{slo_name},{100 * (1.0 - breaches / (timespan / 300000))}")
