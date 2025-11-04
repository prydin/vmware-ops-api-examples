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


parser = argparse.ArgumentParser(
    prog='host-profile-collector',
    description='Collects information about host profiles',
)
parser.add_argument('-H', '--host', required=True, help="The address of the VCF Ops host")
parser.add_argument('-u', '--user', required=True, help="The VCF Ops user")
parser.add_argument('-p', '--password', required=True, help="The VCF Ops password")
parser.add_argument("-a", '--authsource', required=False, help="The VCF Ops authentication source. Default is Local")
parser.add_argument("-l", "--lookback", required=False, default="30", help="Kookback period (days)")
parser.add_argument('-U', '--unsafe', required=False, action="store_true", help="Skip certificate checking (this is unsafe!)")
parser.add_argument('-v', '--vcuser', required=True, help="The vCenter user")
parser.add_argument('-V', '--vchost', required=True, help="The vCenter host")
parser.add_argument('-W', '--vcpassword', required=True, help="The vCenter password")




args = parser.parse_args()

vc_host = args.vchost
vc_user = args.vcuser
vc_password = args.vcpassword
vc_port = 443
vcenter = SmartConnect(host=vc_host,
                                user=vc_user,
                                pwd=vc_password,
                                port=vc_port,
                                disableSslCertValidation=True)

ssl_context = ssl._create_unverified_context()
login(args.host, args.user, args.password, args.authsource)

content = vcenter.RetrieveContent()
vcenter_id = content.about.instanceUuid
hp_manager = content.hostProfileManager
compliance_manager = content.complianceManager
profiles = hp_manager.profile
host_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                        [vim.HostSystem],
                                                        True)
for profile in profiles:
    print(profile, profile.name, profile.validationState, profile.validationFailureInfo, profile._moId, profile.referenceHost, profile.entity)

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
        print(add_properties(resource_id, { "uniqueId": unique_key, "vcenter": args.vchost}))
    else:
        resource_id = resources[0]["identifier"]
    add_metrics(resource_id, {"validationStatus": profile.validationState})

    # Iterate over associated hosts

    #result = compliance_manager.CheckCompliance([profile], profile.entity)
    #print(result)
    for host in profile.entity:
        print(host.complianceCheckResult.complianceStatus, host.complianceCheckResult.checkTime, len(host.complianceCheckResult.failure), host.value, host.config, dir(host))
        unique_key = vcenter_id + ":" + host._GetMoId()
        query = {
            "propertyName": "uniqueId",
            "propertyValue": unique_key
        }
        resources = query_resource("HostProfileAdapter", "HostCompliance", query)
        if len(resources) == 0:
            resource = create_resource("HostProfileAdapter", "HostCompliance", host.name,
                                       {"moid": host._GetMoId(), "vcenterUuid": vcenter_id})
            resource_id = resource["identifier"]
            print(add_properties(resource_id, {"uniqueId": unique_key }))
        else:
            resource_id = resources[0]["identifier"]
        cc_result = host.complianceCheckResult
        add_metrics(resource_id, {"complianceStatus": cc_result.complianceStatus, "lastCheck": str(cc_result.checkTime)})

        # validation = hp_manager.RetrieveCompliance(host=[host])

    #print(profile.name, profile.host, profile.fautls, profile.failures)

host_view.Destroy()




