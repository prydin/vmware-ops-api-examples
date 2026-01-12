import argparse
import ssl
import json
import sys
import time
from functools import lru_cache
from time import sleep
from urllib.error import URLError
from urllib.parse import urlencode
from urllib import request
import csv

PAGESIZE = 1000

url_base = ""

headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Ops-API-use-unsupported": "true"}

ssl_context = ssl.create_default_context()

# Change these constants to suit your environment
VM_COLUMN_NUMBER = 0                # The column containing the VM name
APP_COLUMN_NUMBER = 1               # The column containing the application name
GROUP_TYPE = "CMDB Discovered App"  # The group type for application grouping
TAG_FIELD = "ServiceNow|Tags"      # The VN field to use for application tagging

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


def post(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    if response.status not in range(200,299):
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode))
    content = response.read().decode("UTF-8")
    if len(content) == 0:
        return None
    return json.loads(content)

def get_resources_by_name(adapter_kind, resource_kind, name):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "name": [name]
    }
    resource_response = post("/api/resources/query", payload)
    return resource_response["resourceList"]

@lru_cache(maxsize=100000)
def get_resource_by_name(adapter_kind, resource_kind, name):
    resources = get_resources_by_name(adapter_kind, resource_kind, name)
    for r in resources:
        if r["resourceKey"]["name"] == name:
            return r
    return None


parser = argparse.ArgumentParser(
    prog='reset-capacity',
    description='Resets capacity metrics for a cluster',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument('-c', '--cluster', required=True)
parser.add_argument('-U', '--unsafe', required=False, action="store_true")

args = parser.parse_args()

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

cluster_name = args.cluster
cluster_resource = get_resource_by_name("VMWARE", "ClusterComputeResource", cluster_name)
if not cluster_resource:
    print("Cluster %s not found" % cluster_name)
    exit(1)
cluster_id = cluster_resource["identifier"]
print("Resetting capacity metrics for cluster %s (id: %s)" % (cluster_name, cluster_id))
payload = {}
headers["X-Ops-API-use-unsupported"] = "true"
post(f"/internal/resources/capacitymps/reset?resourceId={cluster_id}", payload)
print("Capacity metrics reset initiated")
