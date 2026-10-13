import argparse
import ssl
import json
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from time import sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib import request

# Generates (or fetches the latest) VCF Operations report for a single resource and
# downloads it as CSV or PDF. Flow: authenticate -> look up resource -> look up report
# definition -> run report and wait (or find the latest run) -> download.

PAGESIZE = 1000

# All Suite API endpoints live under https://<host>/suite-api
url_base = ""

# The Suite API returns XML by default, so JSON must be requested explicitly.
# X-Ops-API-use-unsupported is needed for endpoints marked "internal"/unsupported
# in the API docs; harmless for the public ones.
headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Ops-API-use-unsupported": "true"}

ssl_context = ssl.create_default_context()


def open_url(rq, what, data=None):
    # urlopen raises on any non-2xx status, and the response body (where both the
    # Suite API and the Identity Broker explain what went wrong) is otherwise lost.
    try:
        return request.urlopen(url=rq, context=ssl_context, data=data)
    except HTTPError as e:
        body = e.read().decode("UTF-8", errors="replace").strip()
        sys.stderr.write(f"{what} failed: HTTP {e.code} {e.reason}\n{body}\n")
        sys.exit(1)

def login(host, username, password, auth_source=None):
    # Exchange username/password for a session token (valid for ~6 hours) that is
    # sent with every subsequent request.
    global url_base
    url_base = "https://" + host + "/suite-api"
    cred_payload = {"username": username, "password": password}
    # authSource is the name of the identity source (e.g. an LDAP/AD source configured
    # in Operations). Omit it for local Operations users.
    if auth_source:
        cred_payload["authSource"] = auth_source
    credentials = json.dumps(cred_payload)

    rq = request.Request(url=url_base + "/api/auth/token/acquire", data=credentials.encode("UTF-8"), headers=headers)
    response = open_url(rq, "Login to VCF Operations")
    json_data = json.loads(response.read().decode())
    token = json_data["token"]
    # "vRealizeOpsToken" is the legacy name of the scheme; newer versions also accept "OpsToken".
    headers["Authorization"] = "vRealizeOpsToken " + token

def login_with_api_token(host, api_token, idb_url):
    # VCF 9.1+: exchange the long-lived API token for a short-lived bearer token
    # at the VCF Identity Broker (IDB), then use it directly against the Suite API.
    global url_base
    url_base = "https://" + host + "/suite-api"

    # Accept a bare host name and default to the OAuth2 token endpoint of the
    # default "CUSTOMER" tenant.
    if "://" not in idb_url:
        idb_url = "https://" + idb_url
    idb_url = idb_url.rstrip("/")
    if "/acs/" not in idb_url:
        idb_url += "/acs/t/CUSTOMER/token"

    # Standard OAuth2 form post, using a VCF-specific grant type for API tokens.
    form = urlencode({
        "grant_type": "urn:custom:vcf:params:oauth:grant-type:api-token",
        "api_token": api_token.strip(),
    })
    rq = request.Request(url=idb_url, data=form.encode("UTF-8"), headers={
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    response = open_url(rq, f"API token exchange at {idb_url}")
    json_data = json.loads(response.read().decode())
    headers["Authorization"] = "Bearer " + json_data["access_token"]

def get(uri):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = open_url(rq, "GET " + uri)
    return json.loads(response.read().decode("UTF-8"))

def get_streaming(uri, out):
    # Copies the response body to a file in chunks, so large reports aren't held in memory.
    rq = request.Request(url=url_base + uri, headers=headers)
    response = open_url(rq, "GET " + uri)
    while True:
        content = response.read(10000)
        if not content:
            break
        out.write(content)

def post(uri, data):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = open_url(rq, "POST " + uri, data=json.dumps(data).encode("UTF-8"))
    return json.loads(response.read().decode("UTF-8"))

def get_resource_by_name(adapter_kind, resource_kind, name):
    # In Operations, every monitored object is a "resource", identified by its adapter
    # kind (the integration that collects it, e.g. VMWARE for vCenter) and resource
    # kind (its type, e.g. Datacenter, ClusterComputeResource, VirtualMachine).
    # Names are only unique within a kind, hence all three criteria.
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "name": [name]
    }
    resource_response = post("/api/resources/query", payload)
    resource_list = resource_response["resourceList"]
    # Names aren't guaranteed unique, so more than one hit is possible.
    if len(resource_list) == 0:
        raise Exception("No matching resources found")
    if len(resource_list) > 1:
        raise Exception("More than one resource matched")
    return resource_list[0]

def parse_completion_time(value):
    # The API doesn't specify the format of completionTime, so accept the common ones.
    if value is None:
        return None
    if isinstance(value, (int, float)) or str(value).isdigit():
        return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
    value = str(value).strip()
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        pass
    # Java Date.toString() style, e.g. "Tue Oct 13 11:27:06 UTC 2026". Time zone is ignored.
    parts = value.split()
    if len(parts) == 6:
        try:
            return datetime.strptime(" ".join(parts[:4] + parts[5:]), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None

def find_latest_report(report_definition_id, resource_id):
    # Each run of a report is stored as a separate "report" object. Only resourceId can
    # be filtered server-side, so filter by definition and status here.
    candidates = []
    page = 0
    # Results are paged (page numbers are 0-based).
    while True:
        query = urlencode({"resourceId": resource_id, "page": page, "pageSize": PAGESIZE})
        result = get(f"/api/reports?{query}")
        batch = result.get("reports", [])
        for r in batch:
            if r.get("reportDefinitionId") == report_definition_id and r.get("resourceId") == resource_id \
                    and str(r.get("status", "")).upper() == "COMPLETED":
                candidates.append(r)
        total = result.get("pageInfo", {}).get("totalCount")
        page += 1
        if len(batch) < PAGESIZE or (total is not None and page * PAGESIZE >= total):
            break
    if not candidates:
        return None
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    # Stable sort, so reports with unparseable times keep their API order.
    candidates.sort(key=lambda r: parse_completion_time(r.get("completionTime")) or epoch)
    return candidates[-1]

# Parse arguments
parser = argparse.ArgumentParser(
    prog='getmetric',
    description='Runs a report and downloads the result',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=False)
parser.add_argument('-p', '--password', required=False)
parser.add_argument('-t', '--api-token', required=False, help="VCF 9.1+ API token. Requires --idb-url. Mutually exclusive with --user/--password")
parser.add_argument('-I', '--idb-url', required=False, help="VCF Identity Broker host or URL, e.g. https://idb.example.com (token endpoint /acs/t/CUSTOMER/token is appended if no /acs/ path is given)")
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument("-k", '--adapterkind', required=False, default="VMWARE")
parser.add_argument('-r', '--resourcekind', required=True)
parser.add_argument('-n', '--resourcename', required=True)
parser.add_argument('-R', '--reportname', required=True)
parser.add_argument('-o', '--output', required=False)
parser.add_argument('--format', choices=('pdf', 'csv'), default='csv', help="Download format (default: csv). PDF requires --output")
parser.add_argument('-U', '--unsafe', required=False, action="store_true")
parser.add_argument('-N', '--nogenerate', required=False, action="store_true", help="Don't run the report. Download the latest completed run of it for the specified resource instead")


args = parser.parse_args()

if args.format == "pdf" and not args.output:
    parser.error("--output is required when --format is pdf")

if args.api_token:
    if args.user or args.password:
        parser.error("--api-token is mutually exclusive with --user and --password")
    if not args.idb_url:
        parser.error("--idb-url is required when --api-token is specified")
else:
    if args.idb_url:
        parser.error("--idb-url can only be used together with --api-token")
    if not (args.user and args.password):
        parser.error("either --user and --password, or --api-token and --idb-url must be specified")

# Create a client connection
if args.unsafe:
    ssl_context = ssl._create_unverified_context()
try:
    if args.api_token:
        login_with_api_token(args.host, args.api_token, args.idb_url)
    else:
        login(args.host, args.user, args.password, args.authsource)
except URLError as e:
    if "certificate" in str(e):
        sys.stderr.write("The server appears to have a self-signed certificate. Override by adding the --unsafe option (not recommended in production)\n")
        sys.exit(1)
    else:
        raise e

# A report is produced by running a report definition (the template you see under
# Reports in the UI) against a root resource. Start by finding the resource.
resources = get_resource_by_name(args.adapterkind, args.resourcekind, args.resourcename)
resource_id = resources["identifier"]

# Next, look up the report definition by name. If several match, the first one is used.
report_query = {"name": args.reportname }
reports = get(f"/api/reportdefinitions?{urlencode(report_query)}")
report_definition_id = reports["reportDefinitions"][0]["id"]

if args.nogenerate:
    latest = find_latest_report(report_definition_id, resource_id)
    if latest is None:
        sys.stderr.write(f"Report '{args.reportname}' has never been run for resource '{args.resourcename}'\n")
        sys.exit(1)
    run_id = latest["id"]
else:
    # Start a report run. This is asynchronous: the call returns immediately with the
    # ID of the new run while generation happens in the background.
    report_spec = {
        "reportDefinitionId": report_definition_id,
        "resourceId": resource_id
    }
    report_run = post("/api/reports", report_spec)

    run_id = report_run["id"]

    # Poll until generation is done.
    while True:
        sleep(5)
        report_run = get(f"/api/reports/{run_id}")
        if report_run["status"] == "COMPLETED":
            break

# Download the generated report. format can also be "pdf" if the report definition
# produces PDF output.
if args.output:
    with open(args.output, "wb") as f:
        get_streaming(f"/api/reports/{run_id}/download?format={args.format}", f)
else:
    get_streaming(f"/api/reports/{run_id}/download?format={args.format}", sys.stdout.buffer)