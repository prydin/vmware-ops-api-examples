import argparse
import ssl
import json
import sys
import time
from functools import lru_cache
from time import sleep
from urllib.error import URLError
from urllib.parse import urlencode
from urllib import request
import csv

PAGESIZE = 1000

url_base = ""

headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Ops-API-use-unsupported": "true"}

ssl_context = ssl.create_default_context()

# Change these constants to suit your environment
VM_COLUMN_NUMBER = 0                # The column containing the VM name
APP_COLUMN_NUMBER = 1               # The column containing the application name
GROUP_TYPE = "CMDB Discovered App"  # The group type for application grouping
TAG_FIELD = "ServiceNow|Tags"      # The VN field to use for application tagging

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


parser = argparse.ArgumentParser(
    prog='import-groups',
    description='Imports groups from a CSV file',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False, default="Local")
parser.add_argument("-i", '--input', required=False)
parser.add_argument("-o", '--output', required=False)
parser.add_argument('-U', '--unsafe', required=False, action="store_true", help="Ignore certificate validation errors. Not recommended in production")




args = parser.parse_args()
url_base = f"https://{args.host}:9543/api/v2"

if args.input and args.output:
    print("--in and --out are mutually exclusive")
    sys.exit(1)

if not (args.input or args.output):
    print("Either --in and --out must be specified")
    sys.exit(1)


# Create a client connection
if args.unsafe:
    ssl_context = ssl._create_unverified_context()

payload = {
    "username": args.user,
    "password": args.password,
    "provider": args.authsource
}
result = post("/sessions", payload)
headers["Authorization"] = "Bearer " + result["sessionId"]

if args.output:
    with open(args.output, "w+t") as out:
        alerts = get("/alerts")
        webhooks = get("/notification/webhook")
        data = {
            "alerts": alerts,
            "webhooks": webhooks
        }
        json.dump(data, out)
elif args.input:
    with open(args.input, "r+t") as inp:
        data = json.load(inp)
        alerts = data["alerts"]
        webhooks = data["webhooks"]

        # Load current alerts to build a dict of existing names
        local_alerts = get("/alerts")
        alert_exists = {}
        for alert in local_alerts:
            alert_exists[alert["name"]] = True

        # Build webhook cross-reference tables
        incoming_webhooks = {}
        for webhook in webhooks:
            incoming_webhooks[webhook["id"]] = webhook["name"]
        webhooks = get("/notification/webhook")
        local_webhooks = {}
        for webhook in webhooks:
            local_webhooks[webhook["name"]] = webhook["id"]

        # Add alerts one by one
        for alert in alerts:
            if alert["name"] in alert_exists:
                continue
            new_webhooks = []
            for webhook in alert["recipients"]["webhookIds"]:
                new_webhooks.append(local_webhooks[incoming_webhooks[webhook]])
            alert["recipients"]["webHooks"] = new_webhooks
            post("/alerts", alert)

