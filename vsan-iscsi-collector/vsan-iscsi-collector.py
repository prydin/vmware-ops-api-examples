#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import ssl
import sys
import time
from urllib import request

from pyVim.connect import SmartConnect
from pyVmomi import vim, SoapStubAdapter

############################################################################################################
# THIS IS EXAMPLE CODE! USE AT YOUR OWN RISK. DO NOT USE IN PRODUCTION ENVIRONMENTS WITHOUT PROPER TESTING AND REVIEW
############################################################################################################.

# Constants
PAGESIZE = 1000
url_base = ""
headers = {"Accept": "application/json", "Content-Type": "application/json"}
ssl_context = ssl.create_default_context()

# Logger (configured after parsing args)
logger = logging.getLogger("vsan_iscsi_collector")


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
    logger.debug("POST %s payload=%s", rq.full_url, json.dumps(data))
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


def create_resource_maybe(adapter_type, resource_type, name, unique_key):
    """Create a resource in vROps if it doesn't exist."""
    query = {
        "adapterKind": [adapter_type],
        "resourceKind": [resource_type],
        "propertyName": "uniqueId",
        "propertyValue": unique_key
    }
    resources = query_resource(query)
    if not resources:
        logger.debug("Resource not found, creating: %s %s %s", adapter_type, resource_type, name)
        resource = create_resource(adapter_type, resource_type, name,
                                   {"uniqueId":  unique_key})
        resource_id = resource["identifier"]
        add_properties(resource_id, {"uniqueId": unique_key })
    else:
        resource_id = resources[0]["identifier"]
        logger.debug("Resource exists: %s -> %s", unique_key, resource_id)
    return resource_id


VSAN_API_VC_SERVICE_ENDPOINT = '/vsanHealth'


# Get handles to VSAN objects
def _GetVsanStub(
        stub, endpoint=VSAN_API_VC_SERVICE_ENDPOINT,
        context=None, version='vim.version.version11'
):
    index = stub.host.rfind(':')
    hostname = stub.host[:index]
    port = int(stub.host.split(":")[-1])
    vsanStub = SoapStubAdapter(
        host=hostname,
        port=port,
        path=endpoint,
        version=version,
        sslContext=context
    )
    vsanStub.cookie = stub.cookie
    return vsanStub


# Parse command-line arguments
parser = argparse.ArgumentParser(description='Collects information about vSAN iSCSI LUNs')
parser.add_argument('-H', '--host', required=True, help="vROps host")
parser.add_argument('-u', '--user', required=True, help="vROps user")
parser.add_argument('-p', '--password', required=False, help="vROps password")
parser.add_argument('--passwordfile', required=False, help="vROps password file")
parser.add_argument('-a', '--authsource', help="Authentication source (default: Local)")
parser.add_argument('-U', '--unsafe', action="store_true", help="Skip certificate checking (unsafe!)")
parser.add_argument('-v', '--vcuser', required=True, help="vCenter user")
parser.add_argument('-V', '--vchost', required=True, help="vCenter host")
parser.add_argument('-W', '--vcpassword', required=False, help="vCenter password")
parser.add_argument('--vcpasswordfile', required=False, help="vCenter password file")
parser.add_argument('--verbose', action='store_true', help="Enable verbose logging to stderr")
args = parser.parse_args()

if vcpassword := args.vcpassword is None:
    if args.vcpasswordfile:
        with open(args.vcpasswordfile, 'r') as f:
            args.vcpassword = f.read().strip()
    else:
        print("Either --vcpassword or --vcpasswordfile must be provided", file=sys.stderr)
        sys.exit(1)
if password := args.password is None:
    if args.passwordfile:
        with open(args.passwordfile, 'r') as f:
            args.password = f.read().strip()
    else:
        print("Either --password or --passwordfile must be provided", file=sys.stderr)
        sys.exit(1)

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

# Get handles to VSAN objects
vsan_stub = _GetVsanStub(vcenter._stub, context=ssl_context)

# Create an instance of the performance manager
vsan_perf_mgr = vim.cluster.VsanPerformanceManager(
                                      'vsan-performance-manager',
                                      vsan_stub
                                   )

# Retrieve vCenter content
content = vcenter.RetrieveContent()
cluster_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True)
try:
    for cluster in cluster_view.view:
        spec = vim.cluster.VsanPerfQuerySpec()
        spec.entityRefId = "vsan-iscsi-lun:*"
        endTime = datetime.datetime.now(datetime.UTC)
        startTime = endTime - datetime.timedelta(minutes=10)
        spec.startTime = startTime
        spec.endTime = endTime
        spec.interval = 300

        result = vsan_perf_mgr.QueryVsanPerf(querySpecs=[spec], cluster=cluster)
        for lun in result:
            metrics = {}
            lun_name = lun.entityRefId.split(":")[1]
            resource_id = create_resource_maybe("VSAN_ISCSI", "LUN", lun_name,
                                                args.vchost + ":" + cluster.name + ":" + lun_name)
            for value in lun.value:
                scale = 0.001 if "latency" in value.metricId.label else 1.0 # We want latency number is milliseconds, not microseconds
                metrics[value.metricId.label] = float(value.values.split(",")[-1]) * scale
                logger.debug("Parsed metric for %s: %s=%s", lun_name, value.metricId.label, metrics[value.metricId.label])
            add_metrics(resource_id, metrics)

            # Add relationship to cluster
            clusters = query_resource({ "adapterKind": ["VMWARE"], "resourceKind": ["ClusterComputeResource"], "name": [cluster.name]})
            if clusters:
                cluster_id = clusters[0]["identifier"]
                add_relationships(resource_id, [cluster_id], "PARENT")
finally:
    cluster_view.Destroy()
