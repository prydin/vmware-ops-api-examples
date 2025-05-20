import argparse
import ssl
import json
import sys
from time import sleep
from urllib.error import URLError
from urllib.parse import urlencode
from urllib import request

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
parser.add_argument('-n', '--resourcename', required=True)
parser.add_argument('-R', '--reportname', required=True)
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

# To run a report, we need to find report definition as well as the root resource to run the report against.
# Start by finding the resource. In this case, we'll use a Datacenter as the root resource
resources = get_resource_by_name(args.adapterkind, args.resourcekind, args.resourcename)
resource_id = resources["identifier"]

# Next, we look up the report definition
report_query = {"name": args.reportname }
reports = get(f"/api/reportdefinitions?{urlencode(report_query)}")
report_definition_id = reports["reportDefinitions"][0]["id"]

# Run the report. Create a report request and issue a POST HTTP call
report_spec = {
    "reportDefinitionId": report_definition_id,
    "resourceId": resource_id
}
report_run = post("/api/reports", report_spec)

# Grab the ID of the run so we can check if it's completed.
run_id = report_run["id"]

# Check for completion
while True:
    sleep(5)
    report_run = get(f"/api/reports/{run_id}")
    if report_run["status"] == "COMPLETED":
        break

if args.output:
    with open(args.output, "wb") as f:
        get_streaming(f"/api/reports/{run_id}/download?format=csv", f)
else:
    get_streaming(f"/api/reports/{run_id}/download?format=csv", sys.stdout.buffer)