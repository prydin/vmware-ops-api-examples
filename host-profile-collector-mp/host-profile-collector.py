import json

from pyVmomi import vmodl, vim
from pyVim.connect import SmartConnect


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

def add_metrics(id: str, stats: dict):
    stat_list = []
    for k, v in stats.items():
        stat_list.append({
            "statKey": k,
            "timestamps": [ int(time.time() * 1000) ],
            "values": [v]
        })
    payload = {
        "resource-stat-content": [{
                "id": id,
                "stat-contents": stat_list,
        }]
    }
    return post(f"/api/resources/stats", payload)


def query_resource(adapter_kind, resource_kind, query, page = 0):
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", query)
    return resource_response["resourceList"]

def submit_metrics(adapter_kind, resource_kind, resource_id, metric_key, timestamps, data):
    pass

vc_host = "vc-01.vcf-lab.local"
vc_user = "administrator@vsphere.local"
vc_password = "VMware123!VMware123!"
vc_port = 443
vcenter = SmartConnect(host=vc_host,
                                user=vc_user,
                                pwd=vc_password,
                                port=vc_port,
                                disableSslCertValidation=True)

ssl_context = ssl._create_unverified_context()
login("192.168.1.220", "admin", "VMware123!")

content = vcenter.RetrieveContent()
vcenter_id = content.about.instanceUuid
hp_manager = content.hostProfileManager
profiles = hp_manager.profile
for profile in profiles:
    print(profile, profile.name, profile.validationState, profile.validationFailureInfo, profile._moId, profile.referenceHost, dir(profile))

    # Check if the resource exists and create it if it doesn't.
    unique_key = vcenter_id + ":" + profile._moId
    query = {
        "propertyName": "uniqueId",
        "propertyValue": unique_key
    }
    resources = query_resource("HostProfileAdapter", "HostProfile", query)
    if len(resources) == 0:
        resource = create_resource("HostProfileAdapter", "HostProfile", profile.name,
                        {"moid": profile._moId, "vcenterUuid": vcenter_id})
        resource_id = resource["identifier"]
        print(add_properties(resource_id, { "uniqueId": unique_key}))
    else:
        resource_id = resources[0]["identifier"]
    add_metrics(resource_id, {"validationStatus": profile.validationState})

    #print(profile.name, profile.host, profile.fautls, profile.failures)






