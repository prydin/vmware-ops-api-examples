import json

from pyVmomi import vim
from pyVim.connect import SmartConnect


import argparse
import ssl
import json
import time
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

def add_relationships(id: str, targets: list[str], relationship_type: str):
    payload = {
        "uuids": targets
    }
    return post(f"/api/resources/{id}/relationships/{relationship_type}", payload)


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


def query_resource(query, page = 0):
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", query)
    return resource_response["resourceList"]

def create_resource_maybe(adapter_type, resource_type, vc_object, vcenter_id):
    moid = vc_object._moId
    unique_key = vcenter_id + ":" + moid
    query = {
        "adapterKind": [adapter_type],
        "resourceKind": [resource_type],
        "propertyName": "uniqueId",
        "propertyValue": unique_key
    }
    resources = query_resource(query)
    if len(resources) == 0:
        resource = create_resource(adapter_type, resource_type, vc_object.name,
                                   {"moid": moid, "vcenterUuid": vcenter_id})
        resource_id = resource["identifier"]
        print(add_properties(resource_id, {"uniqueId": unique_key, "vcenter": vcenter_id}))
    else:
        resource_id = resources[0]["identifier"]
    return resource_id



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

    # Creat4e host profile if needed
    profile_id = create_resource_maybe("HostProfileAdapter", "HostProfile", profile, vcenter_id)

    # Link host profile to vCenter
    vcenters = query_resource({"adapterKind": ["VMWARE"], "resourceKind": ["vCenter"], "propertyName": "summary|vcuuid", "propertyValue": vcenter_id})
    if len(vcenters) == 1:
        add_relationships(profile_id, [vcenters[0]["identifier"]], "parents")

    # Record host compliance status
    noncompliant_hosts = 0
    for host in profile.entity:
        if not isinstance(host, vim.HostSystem):
            continue # Skip clusters for now
        # Record host profile metrics
        resource_id = create_resource_maybe("HostProfileAdapter", "HostCompliance", host, vcenter_id)
        cc_result = host.complianceCheckResult
        if host.complianceCheckResult.complianceStatus == "nonCompliant":
            noncompliant_hosts += 1
        time_since_last_check = int((time.time() - cc_result.checkTime.timestamp()) / 8640) / 10
        stats = {
            "complianceStatus": cc_result.complianceStatus,
            "lastCheck": str(cc_result.checkTime),
            "timeSinceLastCheck": time_since_last_check,
            "failures": len(cc_result.failure)}
        add_metrics(resource_id, stats)

        # Link HostCompliance to host
        ops_hosts = query_resource({"adapterKind": ["VMWARE"], "resourceKind": ["HostSystem"], "name": [host.name]})
        if len(ops_hosts) == 0:
            continue
        add_relationships(resource_id, [ops_hosts[0]["identifier"], profile_id], "parents")
    add_metrics(profile_id, {"validationStatus": profile.validationState, "nonCompliantHosts": noncompliant_hosts})


host_view.Destroy()