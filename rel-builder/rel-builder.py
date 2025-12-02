import argparse
import ssl
import re
import json
import sys
from urllib.error import URLError, HTTPError
from urllib import request

PAGESIZE = 1000

url_base = ""
headers = {"Accept": "application/json", "Content-Type": "application/json"}
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


def get_properties_bulk(ids, props):
    payload = {
        "resourceIds": ids,
        "propertyKeys": props,
        "instanced": True
    }
    result = post("/api/resources/properties/latest/query", payload)
    properties = result["values"]

    # Transform the result into a more convenient format
    prop_dict = {}
    for item in properties:
        resource_id = item["resourceId"]
        prop_contents = item.get("property-contents", {}).get("property-content", [])
        prop_dict[resource_id] = {}
        for prop in prop_contents:
            stat_key = prop["statKey"]
            values = prop.get("values", [])
            if values:
                prop_dict[resource_id][stat_key] = values[0]
            else:
                prop_dict[resource_id][stat_key] = None
    return prop_dict


def get_resources(adapter_kind, resource_kind, page):
    """
    Queries resources by resource type from the vRealize Operations API.

    Args:
        adapter_kind (str): The adapter kind key.
        resource_kind (str): The resource kind key.
        page (int): The page number for pagination.

    Returns:
        list: A list of resources matching the query.
    """
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
    }
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response.get("resourceList", [])


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
        payload["name"] = [name]
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response.get("resourceList", [])


def get_metrics(resource_ids, metric_keys, start_time, interval, rollup):
    """
    Retrieves metrics for the specified resources from the vRealize Operations API.

    Args:
        resource_ids (list): A list of resource IDs to query metrics for.
        metric_keys (list): A list of metric keys to retrieve.
        start_time (int): The start time for the metric query (in milliseconds since epoch).
        interval (int): The interval quantifier for the metrics (in minutes).
        rollup (str): The rollup type for the metrics (e.g., "AVG", "SUM").

    Returns:
        dict: The JSON-decoded response containing the metrics.
    """
    payload = {
        "resourceId": resource_ids,
        "statKey": metric_keys,
        "begin": start_time,
        "rollUpType": rollup,
        "intervalType": "MINUTES",
        "intervalQuantifier": interval,
    }
    return post("/api/resources/stats/query", payload)

def add_relation(source_id, target_id, relation_type):
    """
    Adds a relation between two resources in vRealize Operations.

    Args:
        source_id (str): The identifier of the source resource.
        target_id (str): The identifier of the target resource.
        relation_type (str): The type of relation to create.

    Returns:
        dict: The JSON-decoded response from the API.
    """
    payload = {
        "uuids": [target_id]
    }
    return post(f"/api/resources/{source_id}/relationships/{relation_type}", payload)


def main():
    """
    Main function to build relationships between resources based on properties.
    """
    parser = argparse.ArgumentParser(prog="rel-builder", description="Builds relationships between resources based on properties")
    parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
    parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
    parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
    parser.add_argument("-a", "--authsource", required=False, help="The VCF Ops authentication source. Default is Local")
    parser.add_argument("--reltype", required=True, help="Relation type to create")
    parser.add_argument("--sourcekind", required=True, help="Resource kind of source")
    parser.add_argument("--targetkind", required=True, help="Resource kind of target")
    parser.add_argument("--property", required=True, help="Property used for linking")
    parser.add_argument("--matchre", required=False, help="Name matching regular expression")
    parser.add_argument("--extractre", required=False, help="Name extraction regular expression")
    parser.add_argument("--ignorecase", required=False, action="store_true", help="Ignore case in name matching")
    parser.add_argument("-U", "--unsafe", required=False, action="store_true", help="Skip certificate checking (this is unsafe!)")

    args = parser.parse_args()

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

    page = 0
    while True:
        if ":" in args.sourcekind:
            (source_adapter, source_kind) = args.sourcekind.split(":")
        else:
            source_adapter = "VMWARE"
            source_kind = args.sourcekind
        if ":" in args.targetkind:
            (target_adapter, target_kind) = args.targetkind.split(":")
        else:
            target_adapter = "VMWARE"
            target_kind = args.targetkind
        resources = get_resources(source_adapter, source_kind, page)
        if not resources or len(resources) == 0:
            break
        properties = get_properties_bulk(
            [r["identifier"] for r in resources],
            [args.property]
        )
        for id, prop_values in properties.items():
            prop_value = prop_values.get(args.property, None)
            if not prop_value:
                continue

            # Extract value using regexp
            if args.extractre:
                pattern = re.compile(args.extractre)
                match = pattern.match(prop_value)
                if not match:
                    print(f"Source resource {id} property {args.property}='{prop_value}' does not match extraction regexp")
                    continue
                prop_value = match.group(1)
            targets = get_resources_by_name(
                target_adapter,
                target_kind,
                prop_value,
                0
            )
            # Filter targets by regexp
            if args.matchre:
                regexp = args.matchre.replace("{}", prop_value)
                pattern = re.compile(regexp, re.IGNORECASE if args.ignorecase else 0)
                targets = [t for t in targets if pattern.match(t["resourceKey"]["name"])]

            if len(targets) == 0:
                print(f"Source resource {id} property {args.property}='{prop_value}' has no matching target resource")
                continue
            elif len(targets) > 1:
                print(f"Source resource {id} property {args.property}='{prop_value}' has multiple matching target resources")
                continue
            target = targets[0]
            print(f"Source resource {id} property {args.property}='{prop_value}' maps to target resource {target['identifier']}")
            add_relation(id, target["identifier"], args.reltype)
        page += 1

if __name__ == "__main__":
    main()