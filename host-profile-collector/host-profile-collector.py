# python
#!/usr/bin/env python3
"""
host-profile-collector.py

Collects host profile information from vCenter and sends it to vROps.
"""

from pyVmomi import vim
from pyVim.connect import SmartConnect
import argparse
import ssl
import json
import time
import sys
import logging
from urllib import request

# Constants
PAGESIZE = 1000
url_base = ""
headers = {"Accept": "application/json", "Content-Type": "application/json"}
ssl_context = ssl.create_default_context()

# Logger (configured after parsing args)
logger = logging.getLogger("host_profile_collector")


def login(host, username, password, auth_source=None):
    """Authenticate with vROps and retrieve a session token."""
    global url_base
    url_base = f"https://{host}/suite-api"
    credentials = json.dumps({
        "username": username,
        "password": password,
        **({"authSource": auth_source} if auth_source else {})
    }).encode("utf-8")

    rq = request.Request(f"{url_base}/api/auth/token/acquire", data=credentials, headers=headers)
    logger.debug("Requesting auth token: %s", rq.full_url)
    response = request.urlopen(url=rq, context=ssl_context)
    status = response.getcode()
    content = response.read().decode("utf-8")

    if status != 200:
        print(f"{status} {content}", file=sys.stderr)
        sys.exit(1)

    json_data = json.loads(content)
    headers["Authorization"] = "vRealizeOpsToken " + json_data["token"]
    logger.debug("Authentication succeeded, token acquired.")


def post(uri, data):
    """Send a POST request to vROps and return parsed JSON or None."""
    rq = request.Request(f"{url_base}{uri}", data=json.dumps(data).encode("utf-8"), headers=headers)
    logger.debug("POST %s payload keys=%s", rq.full_url, list(data.keys()) if isinstance(data, dict) else None)
    response = request.urlopen(url=rq, context=ssl_context)
    status = response.getcode()
    content = response.read().decode("utf-8")
    logger.debug("Response status=%s content_len=%d", status, len(content))

    if status not in range(200, 299):
        raise Exception(f"HTTP Status: {status}, details: {content}")

    if not content:
        return None
    return json.loads(content)


def create_resource(adapter_kind, resource_kind, name, keys):
    """Create a resource in vROps."""
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
    logger.debug("Creating resource %s/%s name=%s", adapter_kind, resource_kind, name)
    return post(f"/api/resources/adapterkinds/{adapter_kind}", payload)


def add_relationships(id, targets, relationship_type):
    """Add relationships between resources in vROps."""
    payload = {"uuids": targets}
    logger.debug("Adding relationships for %s -> %s (%s)", id, targets, relationship_type)
    return post(f"/api/resources/{id}/relationships/{relationship_type}", payload)


def add_properties(id, properties):
    """Add properties to a resource in vROps."""
    property_list = []
    for k, v in properties.items():
        property_list.append({
            "statKey": k,
            "timestamps": [int(time.time() * 1000)],
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
    logger.debug("Adding properties to %s: %s", id, list(properties.keys()))
    return post("/api/resources/properties", payload)


def add_metrics(id, stats):
    """Add metrics to a resource in vROps."""
    stat_list = []
    for k, v in stats.items():
        stat_list.append({
            "statKey": k,
            "timestamps": [int(time.time() * 1000)],
            "values": [v]
        })
    payload = {
        "resource-stat-content": [{
            "id": id,
            "stat-contents": stat_list,
        }]
    }
    logger.debug("Adding metrics to %s: %s", id, list(stats.keys()))
    return post("/api/resources/stats", payload)


def query_resource(query, page=0):
    """Query resources in vROps."""
    logger.debug("Querying resources page=%d query=%s", page, query)
    response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", query)
    return response["resourceList"] if response else []


def create_resource_maybe(adapter_type, resource_type, vc_object, vcenter_id):
    """Create a resource in vROps if it doesn't exist."""
    moid = vc_object._moId
    unique_key = f"{vcenter_id}:{moid}"
    query = {
        "adapterKind": [adapter_type],
        "resourceKind": [resource_type],
        "propertyName": "uniqueId",
        "propertyValue": unique_key
    }
    resources = query_resource(query)
    if not resources:
        logger.debug("Resource not found, creating: %s %s %s", adapter_type, resource_type, vc_object.name)
        resource = create_resource(adapter_type, resource_type, vc_object.name,
                                   {"moid": moid, "vcenterUuid": vcenter_id})
        resource_id = resource["identifier"]
        add_properties(resource_id, {"uniqueId": unique_key, "vcenter": vcenter_id})
    else:
        resource_id = resources[0]["identifier"]
        logger.debug("Resource exists: %s -> %s", unique_key, resource_id)
    return resource_id


# Parse command-line arguments
parser = argparse.ArgumentParser(description='Collects information about host profiles')
parser.add_argument('-H', '--host', required=True, help="vROps host")
parser.add_argument('-u', '--user', required=True, help="vROps user")
parser.add_argument('-p', '--password', required=True, help="vROps password")
parser.add_argument('-a', '--authsource', help="Authentication source (default: Local)")
parser.add_argument('-U', '--unsafe', action="store_true", help="Skip certificate checking (unsafe!)")
parser.add_argument('-v', '--vcuser', required=True, help="vCenter user")
parser.add_argument('-V', '--vchost', required=True, help="vCenter host")
parser.add_argument('-W', '--vcpassword', required=True, help="vCenter password")
parser.add_argument('--verbose', action='store_true', help="Enable verbose logging to stderr")
args = parser.parse_args()

# Configure logging based on verbose flag
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logger.addHandler(handler)
logger.propagate = False
logger.setLevel(logging.DEBUG if args.verbose else logging.WARNING)

# Update SSL context if unsafe mode is enabled
if args.unsafe:
    ssl_context = ssl._create_unverified_context()

# Connect to vCenter
vcenter = SmartConnect(host=args.vchost, user=args.vcuser, pwd=args.vcpassword, port=443, disableSslCertValidation=True)
logger.debug("Connected to vCenter %s as %s", args.vchost, args.vcuser)

# Authenticate with vROps
login(args.host, args.user, args.password, args.authsource)

# Retrieve vCenter content
content = vcenter.RetrieveContent()
vcenter_id = content.about.instanceUuid
hp_manager = content.hostProfileManager
profiles = hp_manager.profile
host_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)

# Process host profiles
for profile in profiles:
    logger.debug("Processing profile: %s (%s)", getattr(profile, "name", "<no-name>"), getattr(profile, "_moId", "<no-moid>"))
    profile_id = create_resource_maybe("HostProfileAdapter", "HostProfile", profile, vcenter_id)

    vcenters = query_resource({
        "adapterKind": ["VMWARE"],
        "resourceKind": ["vCenter"],
        "propertyName": "summary|vcuuid",
        "propertyValue": vcenter_id
    })
    if vcenters:
        add_relationships(profile_id, [vcenters[0]["identifier"]], "parents")

    noncompliant_hosts = 0
    for host in profile.entity:
        print(host)
        if not isinstance(host, vim.HostSystem):
            continue
        resource_id = create_resource_maybe("HostProfileAdapter", "HostCompliance", host, vcenter_id)
        cc_result = host.complianceCheckResult
        if cc_result.complianceStatus == "nonCompliant":
            noncompliant_hosts += 1
        add_metrics(resource_id, {
            "complianceStatus": cc_result.complianceStatus,
            "lastCheck": str(cc_result.checkTime),
            "timeSinceLastCheck": int((time.time() - cc_result.checkTime.timestamp()) / 8640) / 10,
            "failures": len(cc_result.failure)
        })
        ops_hosts = query_resource({
            "adapterKind": ["VMWARE"],
            "resourceKind": ["HostSystem"],
            "name": [host.name]
        })
        if ops_hosts:
            add_relationships(resource_id, [ops_hosts[0]["identifier"], profile_id], "parents")
    add_metrics(profile_id, {"validationStatus": profile.validationState, "nonCompliantHosts": noncompliant_hosts})

host_view.Destroy()