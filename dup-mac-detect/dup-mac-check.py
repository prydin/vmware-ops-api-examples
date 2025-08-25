import argparse
import ssl
import json
import sys
import re
from urllib.error import URLError
from urllib import request

PAGESIZE = 1000

url_base = ""

# We don't know how many NICs the VMs will have, so make let's build a query
# matching the first 50.
nics = []
for i in range(50):
    nics.append(f"net:{4000+i}|mac_address")

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

def get_properties_bulk(ids, props):
    payload = {
        "resourceIds": ids,
        "propertyKeys": props,
        "instanced": True
    }
    result = post("/api/resources/properties/latest/query", payload)
    return result["values"]


# MAIN PROGRAM

# Parse command arguments
parser = argparse.ArgumentParser(
    prog='import-groups',
    description='Imports groups from a CSV file',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
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

# Collect all MAC addresses from the disovered VMs and add them to mac_table. If
# there's already an entry for a MAC, we have a conflict.
mac_table = {}

# Discover VMs in chunks of 1000
page = 0
while True:
    # Get the resources. We don't care if the machine is powered on.
    resources = get_resources_by_name("VMWARE", "VirtualMachine", None, page)
    if not resources or len(resources) == 0:
        break
    page += 1

    # Build a dictionary of resource ids mapped to names.
    ids_to_names = {}
    for r in resources:
        ids_to_names[r["identifier"]] = r["resourceKey"]["name"]

    # Get the properties for all VMs in this chunk
    props = get_properties_bulk(list(ids_to_names.keys()), nics)

    # Drill down into the property structure to get the MAC addresses
    for p in props:
        res_id = p["resourceId"]
        res_name = ids_to_names[res_id]
        for content in p["property-contents"]["property-content"]:
            for mac in content["values"]:

                # Already in the MAC table? We have a conflict!
                if mac in mac_table:
                    print(f"VM {res_name} has a duplicate MAC address ({mac}). Conflicts with {mac_table[mac]}")
                else:
                    mac_table[mac] = res_name

