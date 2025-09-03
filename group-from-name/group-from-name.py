import argparse
import re
import ssl
import json
import sys
import time
from functools import lru_cache
from time import sleep
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
from urllib import request
import csv

PAGESIZE = 1000

url_base = ""

headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Ops-API-use-unsupported": "true"}

ssl_context = ssl.create_default_context()

# Change these constants to suit your environment
GROUP_TYPE = "Discovered App"  # The group type for application grouping

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
    json_data = json.loads(response.read().decode())
    token = json_data["token"]
    headers["Authorization"] = "vRealizeOpsToken " + token

def get(uri):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context)
    return json.loads(response.read().decode("UTF-8"))

def delete(uri):
    rq = request.Request(url=url_base + uri, headers=headers, method="DELETE")
    response = request.urlopen(url=rq, context=ssl_context)
    return json.loads(response.read().decode("UTF-8"))

def get_streaming(uri, out):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context)
    while True:
        content = response.read(10000)
        if not content:
            break
        out.write(content)

def post(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    content = response.read().decode("UTF-8")
    if len(content) == 0:
        return None
    return json.loads(content)

def put(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers, method="PUT")
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    return json.loads(response.read().decode("UTF-8"))

def get_resources_by_regex(adapter_kind, resource_kind, regex, page):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
    }
    if regex:
        payload["regex"] = regex
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response["resourceList"]

def get_resources_by_name(adapter_kind, resource_kind, name, page):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
    }
    if name:
        payload["name"] = [ name ]
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response["resourceList"]

def delete_resource(id):
    return delete(f"/api/resources/{id}")

def create_ops_app(name, pattern):
    payload = {
        "resourceKey": {
            "name": name,
            "adapterKindKey": "Container",
            "resourceKindKey": GROUP_TYPE
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
                        "resourceNameConditionRules": [
                            {
                                "name": pattern,
                                "compareOperator": "REGEX"
                            }
                        ]
                    }
                ]
            }
        }
    return post("/api/resources/groups", payload)

def update_ops_app(id, pattern):
    payload = {
        "id": id,
        "resourceKey": {
            "name": name,
            "adapterKindKey": "Container",
            "resourceKindKey": GROUP_TYPE
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
                        "resourceNameConditionRules": [
                            {
                                "name": pattern,
                                "compareOperator": "REGEX"
                            }
                        ]
                    }
                ]
            }
        }
    return put("/api/resources/groups", payload)

def get_resource_by_name(adapter_kind, resource_kind, name):
    resources = get_resources_by_name(adapter_kind, resource_kind, name, 0)
    for r in resources:
        if r["resourceKey"]["name"] == name:
            return r
    return None

filename = "groups.csv"

parser = argparse.ArgumentParser(
    prog='groups-from-name',
    description='Creates groups based on VM names',
)
parser.add_argument('-H', '--host', required=True, help="The VCF Operations host")
parser.add_argument('-u', '--user', required=True, help="The VCF Operations user")
parser.add_argument('-p', '--password', required=True, help="The VCF Operations password")
parser.add_argument("-a", '--authsource', required=False, help="The VCF Operations authentication source")
parser.add_argument('-A', '--appregex', required=True, help="Regexp for obtaining application name from VM name")
parser.add_argument('-f', '--filterregex', required=False, help="Regexp to filter VMs by name (defauls is all VMs)")
parser.add_argument('-U', '--unsafe', required=False, action="store_true", help="Ignore certificate validation errors. Not recommended in production")
parser.add_argument("-l", "--limit", required=False, help="Limit number of VMs to process. Useful for testing/debugging")
parser.add_argument("-F", "--force", required=False, action="store_true", help="Force replacement of existing groups")

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


# Discover VMs in chunks of 1000
page = 0
n = 0
apps_seen = {}
while True:
    # Get the resources. We don't care if the machine is powered on.
    resources = get_resources_by_regex("VMWARE", "VirtualMachine", None, page)
    if not resources or len(resources) == 0:
        break
    page += 1

    # Build a dictionary of resource ids mapped to names.
    for r in resources:
        if args.limit and n >= int(args.limit):
            sys.stderr.write(f"Virtual machine limit reached. Stopping...\n")
            break
        n += 1
        name = r["resourceKey"]["name"]
        if args.filterregex and not re.match(args.filterregex, name):
            continue
        match = re.match(args.appregex, name)
        if not match:
            continue
        app = match.group(1)
        if app in apps_seen:
            continue
        app_pattern = re.sub("\((.*)\)", app, args.appregex)
        app_obj = get_resource_by_name("Container", GROUP_TYPE, app)
        try:
            if app_obj:
                # Already exists? Don't create unlese --force flag is specified
                if args.force:
                    continue
                update_ops_app(app_obj["identifier"], app_pattern)
                sys.stderr.write(f"Update group {app}\n")
                continue
            create_ops_app(app, app_pattern)
            sys.stderr.write(f"Created group {app}\n")
            apps_seen[app] = True
        except HTTPError as e:
            sys.stderr.write(f"API Error {e.status}: {e.fp.read()}")