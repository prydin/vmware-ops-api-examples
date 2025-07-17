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

@lru_cache(maxsize=1000)
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

def set_ops_properties(id, group_names):
    payload = {
        "property-content":
            [
                {
                    "statKey": "ServiceNow|Tags",
                    "timestamps": [ int(time.time())*1000 ],
                    "values": [group_names]
                }
            ]
        }
    return post(f"/api/resources/{id}/properties", payload)

def create_ops_app(name):
    payload = {
        "resourceKey": {
            "name": name,
            "adapterKindKey": "Container",
            "resourceKindKey": "CMDB Discovered App"
        },
        "autoResolveMembership": True,
        "membershipDefinition": {
            "rules":
                [
                    {
                        "resourceKindKey": {
                            "adapterKind": "VMWARE",
                            "resourceKind": "VirtualMachine"
                        },
                        "propertyConditionRules": [
                                {
                                "key": "ServiceNow|Tags",
                                "stringValue": "|" + name + "|",
                                "compareOperator": "CONTAINS"
                            }
                        ]
                    }
                ]
            }
        }
    return post("/api/resources/groups", payload)

filename = "groups.csv"

parser = argparse.ArgumentParser(
    prog='import-groups',
    description='Imports groups from a CSV file',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument('-c', '--csvfile', required=False)
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

# Build application table
vm_to_app = {}
visited_apps = {}
with open(filename, "r") as csvfile:
    rdr = csv.reader(csvfile)
    for row in rdr:
        app = row[1]
        vm = row[0]
        if not app:
            sys.stderr.write(f"Warning: VM {vm} did not have a tag\n")
            continue
        vm_obj = get_resource_by_name("VMWARE", "VirtualMachine", vm)
        if not vm_obj:
            sys.stderr.write(f"Warning: VM {vm} was not found in VCF Ops\n")
            continue
        vm_id = vm_obj["identifier"]
        if vm_id in vm_to_app:
            vm_to_app[vm_id] += "|" + app + "|"
        else:
            vm_to_app[vm_id] = "|" + app + "|"
        visited_apps[app] = True

# Tag VMs with application names
n = 0
for k, v in vm_to_app.items():
    set_ops_properties(k, v)
    if n > 0 and n % 10 == 0:
        sys.stderr.write(f"{n} virtual machines updated\n")
    n += 1
sys.stderr.write(f"{n} virtual machines updated\n")

# Create custom groups as needed
for app in visited_apps.keys():
    app_obj = get_resource_by_name("Container", "CMDB Discovered App", app)
    if not app_obj:
        create_ops_app(app)
        sys.stderr.write(f"Created group {app}\n")