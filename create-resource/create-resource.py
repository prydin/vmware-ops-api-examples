from pyVim.connect import SmartConnect

import argparse
import ssl
import json
import sys
import yaml
import time
from urllib.error import URLError
from urllib import request

from common.client import PAGESIZE

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

def post(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context, data=json.dumps(data).encode("UTF-8"))
    if response.status not in range(200,299):
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode))
    content = response.read().decode("UTF-8")
    if len(content) == 0:
        return None
    return json.loads(content)

def create_resource(adapter_kind, resource_kind, name, keys: dict):
    payload = {
        "resourceKey": {
            "name": name,
            "adapterKindKey": adapter_kind,
            "resourceKindKey": resource_kind
        }
    }
    identifiers = []
    for key, value in keys.items():
        identifiers.append({
            "identifierType": {
                "name": key,
                "dataType": "STRING",
                "isPartOfUniqueness": True
            },
            "value": value
        })
    payload["resourceKey"]["resourceIdentifiers"] = identifiers
    return post(f"/api/resources/adapterkinds/{adapter_kind}", payload)


def add_properties(id: str, properties: dict):
    property_list = []
    for k, v in properties.items():
        property_list.append({
            "statKey": k,
            "timestamps": [ int(time.time() * 1000) ],
            "values": [v]
        })
    payload = {
        "values": [{
                "resourceId": id,
                "property-contents": {
                    "property-content": property_list,
                }
        }]
    }
    return post(f"/api/resources/properties", payload)

PAGESIZE=1000


def query_resource(query, page=0):
    """Query resources in vROps."""
    response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", query)
    return response["resourceList"] if response else []


parser = argparse.ArgumentParser(prog="create-resource", description="Creates a resource in VCF Ops")
parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
parser.add_argument("-a", "--authsource", required=False, help="The VCF Ops authentication source. Default is Local")
parser.add_argument("--adapterkind", required=False, default="VMWARE", help="Adapter kind")
parser.add_argument("--resourcekind", required=True, help="Resource kind")
parser.add_argument("--resourcename", required=True, help="Resource name")
parser.add_argument("--properties", required=False, help="Properties as JSON")
parser.add_argument("-U", "--unsafe", required=False, action="store_true", help="Skip certificate checking (this is unsafe!)")

args = parser.parse_args()

ssl_context = ssl._create_unverified_context()
login(args.host, args.user, args.password)

existing = query_resource({
    "adapterKind": [args.adapterkind],
    "resourceKind": [args.resourcekind],
    "name": [args.resourcename]
})
if existing:
    resource = existing[0]
    print("Found existing resource with ID: " + resource["identifier"])
else:
    resource = create_resource(args.adapterkind, args.resourcekind, args.resourcename, {})
    print("Created resource with ID: " + resource["identifier"])
if args.properties:
    props = json.loads(args.properties)
    add_properties(resource["identifier"], props)
    print("Added properties to resource")
