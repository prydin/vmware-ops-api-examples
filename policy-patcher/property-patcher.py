import argparse
import ssl
import re
import json
import sys
from urllib.error import URLError, HTTPError
from urllib import request
from jsonpath_ng import jsonpath, parse

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


def put(uri, data):
    """
    Sends a PUT request to the vRealize Operations API.

    Args:
        uri (str): The API endpoint URI.
        data (dict): The payload to send in the POST request.

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

def patch(uri, data):
    """
    Sends a PATCH request to the vRealize Operations API.

    Args:
        uri (str): The API endpoint URI.
        data (dict): The payload to send in the POST request.

    Returns:
        dict: The JSON-decoded response from the API.

    Raises:
        Exception: If the HTTP request fails or returns a non-2xx status code.
    """
    payload = json.dumps(data).encode("utf-8")
    rq = request.Request(url_base + uri, data=payload, headers=headers, method="PATCH")
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


def get(uri):
    rq = request.Request(url=url_base + uri, headers=headers)
    response = request.urlopen(url=rq, context=ssl_context)
    if response.status != 200:
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode("UTF-8")))
    return json.loads(response.read().decode("UTF-8"))


def delete(uri):
    rq = request.Request(url=url_base + uri, headers=headers, method="DELETE")
    response = request.urlopen(url=rq, context=ssl_context)
    if response.status not in range(200, 299):
        raise Exception("HTTP Status: %d, details: %s" % (response.status, response.read().decode("UTF-8")))

def get_pollicies():
    return get("/api/policies")["policySummaries"]

def get_policy_details(policy_id, type, adapter_kind=None, resource_kind=None):
    url = f"/api/policies/{policy_id}/settings?type={type}"
    if adapter_kind:
        url += f"&adapterKind={adapter_kind}"
    if resource_kind:
        url += f"&resourceKind={resource_kind}"
    return get(url)

def patch_policy_details(policy_id, type, adapter_kind, resource_kind, settings):
    url = f"/api/policies/{policy_id}/settings?type={type}&adapterKind={adapter_kind}&resourceKind={resource_kind}"
    return patch(url, settings)


def main():
    """
    Main function to build relationships between resources based on properties.
    """
    parser = argparse.ArgumentParser(prog="policy-patcher",
                                     description="Builds relationships between resources based on properties")
    parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
    parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
    parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
    parser.add_argument("-a", "--authsource", required=False,
                        help="The VCF Ops authentication source. Default is Local")
    parser.add_argument("-n", "--name", required=True, help="The name of the policy to patch")
    parser.add_argument("-t", "--type", required=True, help="Policy type")
    parser.add_argument("-k", "--adapter-kind", required=False, default="VMWARE", help="Adapter kind for policy settings")
    parser.add_argument("-r", "--resource-kind", required=True, help="Resource kind for policy settings")
    parser.add_argument("-f", "--file", required=True, help="Path to JSON file containing the properties to patch")
    parser.add_argument("-e", "--expression", required=False, help="JSONPath expression to select properties to patch from the file")
    parser.add_argument("-U", "--unsafe", required=False, action="store_true",
                        help="Skip certificate checking (this is unsafe!)")

    args = parser.parse_args()

    if args.unsafe:
        # Unsafe: accept self-signed certificates
        ssl_context = ssl._create_unverified_context()
        globals()["ssl_context"] = ssl_context

    # Parse the JSON path
    try:
        jsonpath_expr = parse(args.expression)
    except Exception as e:
        sys.stderr.write(f"Invalid JSONPath expression: {e}\n")
        sys.exit(1)

    # Load JSON file
    try:
        with open(args.file, "r") as f:
            replacement = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Failed to load JSON file: {e}\n")
        sys.exit(1)

    try:
        login(args.host, args.user, args.password, args.authsource)
    except URLError as e:
        if "certificate" in str(e).lower():
            sys.stderr.write(
                "The server appears to have a self-signed certificate. Override by adding the --unsafe option (not recommended in production)\n")
            sys.exit(1)
        else:
            raise

    policies = get_pollicies()
    policy = next((p for p in policies if p["name"] == args.name), None)
    if not policy:
        sys.stderr.write(f"Policy with name '{args.name}' not found\n")
        sys.exit(1)
    policy_details = get_policy_details(policy["id"], args.type, args.adapter_kind, args.resource_kind)
    print(policy_details)

    print(jsonpath_expr.find(policy_details))

    for match in jsonpath_expr.find(policy_details):
        print(f"Updating property at path: {match.full_path}")
        match.value.update(replacement)

    print("Updated policy details:")
    print(policy_details)

    patch_policy_details(policy["id"], args.type, args.adapter_kind, args.resource_kind, policy_details)
    print("Policy updated successfully.")



if __name__ == "__main__":
    main()
