import argparse
import ssl
import json
import sys
from urllib.error import URLError
from urllib.parse import urlencode
from urllib import request
import re

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

def post(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    if response.status != 200:
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode))
    return json.loads(response.read().decode("UTF-8"))

def get_resource_by_name(adapter_kind, resource_kind, name):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "name": [name]
    }
    resource_response = post("/api/resources/query", payload)
    resource_list = resource_response["resourceList"]
    if len(resource_list) == 0:
        raise Exception("No matching resources found")
    if len(resource_list) > 1:
        raise Exception("More than one resource matched")
    return resource_list[0]

def get_resource_by_tag(adapter_kind, resource_kind, tag_name, tag_category):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "resourceTag": [ { "category": tag_category, "name": tag_name} ],
    }
    resource_response = post("/api/resources/query", payload)
    resource_list = resource_response["resourceList"]
    if len(resource_list) == 0:
        raise Exception("No matching resources found")
    return resource_list

def get_related_resources(adapter_kind, resource_kind, relationship_type, ids, depth = 1):
    payload = {
        "hierarchyDepth": depth,
        "resourceIds": ids,
        "relationshipType": relationship_type,
        "resourceQuery": {
            "adapterKind": [ adapter_kind ],
            "resourceKind": [ resource_kind ],
        }
    }
    resource_response = post("/api/resources/bulk/relationships", payload)
    relation_list = resource_response.get("resourcesRelations", [])
    if len(relation_list) == 0:
        raise Exception("No matching resources found")
    return relation_list

def get_resource_properties(resource_ids, properties):
    payload = {
        "resourceIds": resource_ids,
        "propertyKeys": properties
    }
    resource_response = post("/api/resources/properties/latest/query", payload)
    resource_map = {}
    resources = resource_response["values"]
    if len(resources) == 0:
        raise Exception("No matching resources found")
    for resource in resources:
        id = resource["resourceId"]
        property_map = {}
        for property in resource["property-contents"]["property-content"]:
            property_map[property["statKey"]] = property["values"][0]
        resource_map[id] = property_map
    return resource_map

def get_resource_property(resource_id, property):
    resource_map = get_resource_properties([resource_id], [property])
    return resource_map.get(resource_id, {}).get(property, None)

# Parse arguments
parser = argparse.ArgumentParser(
    prog='getmetric',
    description='Runs a report and downloads the result',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument("-k", '--adapterkind', required=False, default="VMWARE")
parser.add_argument('-r', '--resourcekind', required=True)
parser.add_argument('-t', '--tag', required=True)
parser.add_argument('-o', '--output', required=False)
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

# Parse tag
parts = re.split(r"=", args.tag)
if len(parts) != 2:
    sys.stderr.write("Tag must be on the format <category>=<name>")
    sys.exit(1)
tag_category = parts[0]
tag_name = parts[1]

# Get resources matching the tag
resources = get_resource_by_tag(args.adapterkind, args.resourcekind, tag_name, tag_category)

# Get the VSAN Clusters for each VM
vsan_relations = get_related_resources("VirtualAndPhysicalSANAdapter", "VirtualSANDCCluster",
                                      "ALL", list(map(lambda r: r["identifier"], resources)), 10)

# Map the datatore encryption status to each VM
encryption_map = {}
for relation in vsan_relations:
    # Get the encryption property
    encrypted = get_resource_property(relation["resource"]["identifier"], "configuration|vsan|encryption")
    for resourceId in relation["relatedResources"]:
        encryption_map[resourceId] = encrypted

# Print the results
for resource in resources:
    print(f"{resource['resourceKey']['name']},{encryption_map.get(resource['identifier'], 'unknown')}")



"""
if args.output:
    with open(args.output, "wb") as f:
        get_streaming(f"/api/reports/{run_id}/download?format=csv", f)
else:
    get_streaming(f"/api/reports/{run_id}/download?format=csv", sys.stdout.buffer)
"""