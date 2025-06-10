import argparse
import ssl
import json
import sys
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
    return json.loads(response.read().decode("UTF-8"))

def put(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers, method="PUT")
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    if response.status not in range(200,299):
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode))
    return json.loads(response.read().decode("UTF-8"))

def get_resources_by_name(adapter_kind, resource_kind, name):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "name": [name]
    }
    resource_response = post("/api/resources/query", payload)
    return resource_response["resourceList"]

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
app_table = {}
with open(filename, "r") as csvfile:
    rdr = csv.reader(csvfile)
    for row in rdr:
        app = row[1]
        vm = row[0]
        if not app:
            sys.stderr.write(f"Warning: VM {vm} did not have a tag\n")
            continue
        app_entry = app_table.get(app, None)
        if not app_entry:
            app_entry = [vm]
            app_table[app] = app_entry
        else:
            app_entry.append(vm)

# Create or update group for each application
for app in app_table:
    vm_ids = []
    for vm_name in app_table[app]:
        vms = get_resources_by_name("VMWARE", "VirtualMachine", vm_name)
        found = False
        for vm in vms:
            if vm["resourceKey"]["name"].lower() == vm_name.lower():
                vm_ids.append(vm["identifier"])
                found = True
        if not found:
            sys.stderr.write(f"Warning: VM {vm_name} was not found in VCF Ops\n")

    # Prepare group payload
    payload = {
            "resourceKey": {
                "name": app,
                "adapterKindKey": "Container",
                "resourceKindKey": "CMDB Discovered App"
            },
            "autoResolveMembership": False,
            "membershipDefinition": {
                "includedResources": vm_ids
            }
    }
    groups = get_resources_by_name("Container", "CMDB Discovered App", app)
    group = None
    for candidate in groups:
        if candidate["resourceKey"]["name"] == app:
            group = candidate
    if not group:
        post("/api/resources/groups", payload)
    else:
        payload["id"] = group["identifier"]
        print(json.dumps(payload))
        put("/api/resources/groups", payload)

