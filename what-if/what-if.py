import argparse
import ssl
import json
import sys
import yaml
import time
from urllib.error import URLError, HTTPError
from urllib import request

PAGESIZE = 1000

url_base = ""
headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Ops-API-use-unsupported": "true"}
ssl_context = ssl.create_default_context()


def _read_response(response):
    """
    Reads the HTTP response and extracts the status code and content.

    Args:
        response: The HTTP response object.

    Returns:
        tuple: A tuple containing the HTTP status code and the response content as a string.
    """
    code = getattr(response, "status", None)
    if code is None:
        try:
            code = response.getcode()
        except Exception:
            code = None
    content = response.read()
    text = content.decode("utf-8") if content else ""
    return code, text


def login(host, username, password, auth_source=None):
    """
    Authenticates with the vRealize Operations API and retrieves a session token.

    Args:
        host (str): The vRealize Operations host.
        username (str): The username for authentication.
        password (str): The password for authentication.
        auth_source (str, optional): The authentication source. Defaults to None.

    Raises:
        SystemExit: If authentication fails or the response does not contain a token.
    """
    global url_base
    url_base = f"https://{host}/suite-api"
    cred_payload = {"username": username, "password": password}
    if auth_source:
        cred_payload["authSource"] = auth_source
    credentials = json.dumps(cred_payload).encode("utf-8")

    rq = request.Request(url_base + "/api/auth/token/acquire", data=credentials, headers=headers, method="POST")
    response = request.urlopen(rq, context=ssl_context)
    code, text = _read_response(response)

    if code != 200:
        sys.stderr.write(f"{code} {text}\n")
        sys.exit(1)

    json_data = json.loads(text)
    token = json_data.get("token")
    if not token:
        sys.stderr.write("Authentication response did not contain a token\n")
        sys.exit(1)
    headers["Authorization"] = f"vRealizeOpsToken {token}"


def put(uri, data):
    """
    Sends a PUT request to the vRealize Operations API.

    Args:
        uri (str): The API endpoint URI.
        data (dict): The payload to send in the PUT request.

    Returns:
        dict: The JSON-decoded response from the API.

    Raises:
        Exception: If the HTTP request fails or returns a non-2xx status code.
    """
    payload = json.dumps(data).encode("utf-8")
    rq = request.Request(url_base + uri, data=payload, headers=headers, method="PUT")
    try:
        response = request.urlopen(rq, context=ssl_context)
    except HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else ""
        raise Exception(f"HTTP Error: {e.code}, details: {body}") from e

    code, text = _read_response(response)
    if not (200 <= (code or 0) < 300):
        raise Exception(f"HTTP Status: {code}, details: {text}")
    if not text:
        return None
    return json.loads(text)

def post(uri, data):
    """
    Sends a POST request to the vRealize Operations API.

    Args:
        uri (str): The API endpoint URI.
        data (dict): The payload to send in the POST request.

    Returns:
        dict: The JSON-decoded response from the API.

    Raises:
        Exception: If the HTTP request fails or returns a non-2xx status code.
    """
    payload = json.dumps(data).encode("utf-8")
    rq = request.Request(url_base + uri, data=payload, headers=headers, method="POST")
    try:
        response = request.urlopen(rq, context=ssl_context)
    except HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else ""
        raise Exception(f"HTTP Error: {e.code}, details: {body}") from e

    code, text = _read_response(response)
    if not (200 <= (code or 0) < 300):
        raise Exception(f"HTTP Status: {code}, details: {text}")
    if not text:
        return None
    return json.loads(text)

def delete(uri, payload = None):
    """
    Sends a DELETE request to the vRealize Operations API.

    Args:
        uri (str): The API endpoint URI.

    Raises:
        Exception: If the HTTP request fails or returns a non-2xx status code.
    """
    rq = request.Request(url_base + uri, headers=headers, method="DELETE", data=json.dumps(payload).encode("utf-8") if payload else None)
    try:
        response = request.urlopen(rq, context=ssl_context)
    except HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else ""
        raise Exception(f"HTTP Error: {e.code}, details: {body}") from e

    code, text = _read_response(response)
    if not (200 <= (code or 0) < 300):
        raise Exception(f"HTTP Status: {code}, details: {text}")

def get(uri):
    """
    Sends a GET request to the vRealize Operations API.

    Args:
        uri (str): The API endpoint URI.

    Returns:
        dict: The JSON-decoded response from the API.

    Raises:
        Exception: If the HTTP request fails or returns a non-2xx status code.
    """
    rq = request.Request(url_base + uri, headers=headers, method="GET")
    try:
        response = request.urlopen(rq, context=ssl_context)
    except HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else ""
        raise Exception(f"HTTP Error: {e.code}, details: {body}") from e

    code, text = _read_response(response)
    if not (200 <= (code or 0) < 300):
        raise Exception(f"HTTP Status: {code}, details: {text}")
    if not text:
        return None
    return json.loads(text)


def get_resources_by_name(adapter_kind, resource_kind, name, page):
    """
    Queries resources by name from the vRealize Operations API.

    Args:
        adapter_kind (str): The adapter kind key.
        resource_kind (str): The resource kind key.
        name (str): The name of the resource to query. If None, all resources are queried.
        page (int): The page number for pagination.

    Returns:
        list: A list of resources matching the query.
    """
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
    }
    if name:
        payload["name"] = [ name ]
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response.get("resourceList", [])

def get_resource_by_name(adapter_kind, resource_kind, name):
    """
    Queries resources by name from the vRealize Operations API, handling pagination.

    Args:
        adapter_kind (str): The adapter kind key.
        resource_kind (str): The resource kind key.
        name (str): The name of the resource to query. If None, all resources are queried.
    Returns:
        list: A resource or None if not found
    """
    page = 0
    while True:
        resources = get_resources_by_name(adapter_kind, resource_kind, name, page)
        if not resources:
            break
        for resource in resources:
            if resource["resourceKey"]["name"] == name:
                return resource
        page += 1
    return None


def create_scenario(scenario_name, description, content, dc_id, cluster_id = None):
    """
    Creates a what-if scenario in the vRealize Operations API.

    Args:
        scenario_name (str): The name of the scenario to create.
        description (str): A description of the scenario.


    Returns:
        dict: The JSON-decoded response containing the created scenario details.
    """
    payload = {
        "name": scenario_name,
        "description": description,
        "scenarioContent": content,
        "actionType": "ADD",
        "contentType": "WORKLOAD",
        "location": {
            "dataCenterId": dc_id,
            "clusterId": cluster_id
        },
        "startDate": int(time.time() * 1000) + 3600,
    }
    return post("/internal/whatif/scenarios", payload)


def format_details(details, key):
    capacity_after = details[key]['availableCapacityAfter'] if details and key in details and 'availableCapacityAfter' in details[key] else 'N/A'
    unit = capacity_after['unit']
    value = capacity_after['value']
    return f"{value} {unit}".strip()

def main():
    """
    Demonstrate how to call the what-if API

    Parses command-line arguments, reads the configuration file, and processes SLOs.
    """
    parser = argparse.ArgumentParser(prog="what-if", description="Demonstrate how to call the what-if API")
    parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
    parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
    parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
    parser.add_argument("-a", "--authsource", required=False, help="The VCF Ops authentication source. Default is Local")
    parser.add_argument("-s", "--scenario", required=True, help="The path to the scenario configuration file")
    parser.add_argument("-d", "--datacenter", required=True, help="The name of the datacenter to run the scenario in")
    parser.add_argument("-c", "--cluster", required=False, help="The name of the cluster to run the scenario in (optional)")
    parser.add_argument("-U", "--unsafe", required=False, action="store_true", help="Skip certificate checking (this is unsafe!)")

    args = parser.parse_args()

    with open(args.scenario) as f:
        scenario = yaml.safe_load(f)

    if args.unsafe:
        # Unsafe: accept self-signed certificates
        ssl_context = ssl._create_unverified_context()
        globals()["ssl_context"] = ssl_context

    try:
        login(args.host, args.user, args.password, args.authsource)
    except URLError as e:
        if "certificate" in str(e).lower():
            sys.stderr.write("The server appears to have a self-signed certificate. Override by adding the --unsafe option (not recommended in production)\n")
            sys.exit(1)
        else:
            raise

    dc = get_resource_by_name("VMWARE", "Datacenter", args.datacenter)
    if not dc:
        sys.stderr.write(f"Datacenter '{args.datacenter}' not found\n")
        sys.exit(1)
    dc_id = dc["identifier"]
    if args.cluster:
        cluster = get_resource_by_name("VMWARE", "ClusterComputeResource", args.cluster)
        if not cluster:
            sys.stderr.write(f"Cluster '{args.cluster}' not found\n")
            sys.exit(1)
        cluster_id = cluster["identifier"]
    else:
        cluster_id = None
    #print(get("/internal/whatif/scenarios"))
    new_scenario = create_scenario("tmp_" + str(time.time()), "", scenario, dc_id, cluster_id)
    scenario_id = new_scenario["id"]
    result = put(f"/internal/whatif/scenarios/run", {"uuids": [ scenario_id]})
    #print(f"Scenario result: {result}")
    delete("/internal/whatif/scenarios", { "uuids": [scenario_id] })
    print("The scenario will " + ("fit" if result["clusterDetails"]["scenarioFit"] else "not fit"))
    for cluster in result["clusterDetails"]["clusterSummaries"]:
        print(f"*** Cluster {cluster['clusterName']} summary ***")
        instance_details = cluster.get("instanceDetails", {})
        print(f"CPU after applying scenario: {format_details(instance_details, 'cpuDemand')}")
        print(f"Memory after applying scenario: {format_details(instance_details, 'memoryDemand')}")
        print(f"Storage after applying scenario: {format_details(instance_details, 'diskDemand')}")



if __name__ == "__main__":
    main()