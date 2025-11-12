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
        payload["name"] = name
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


def main():
    """
    Main function to calculate SLO attainment based on metric limits.

    Parses command-line arguments, reads the configuration file, and processes SLOs.
    """
    parser = argparse.ArgumentParser(prog="slo-calc", description="Calculates SLO attainment based on metric limits")
    parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
    parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
    parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
    parser.add_argument("-a", "--authsource", required=False, help="The VCF Ops authentication source. Default is Local")
    parser.add_argument("-c", "--config", required=True, help="Path to the config file")
    parser.add_argument("-l", "--lookback", required=False, default="30", help="Lookback period (days)")
    parser.add_argument("-U", "--unsafe", required=False, action="store_true", help="Skip certificate checking (this is unsafe!)")

    args = parser.parse_args()
    lookback = int(args.lookback)

    with open(args.config) as f:
        config = yaml.safe_load(f)

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

    for slo in config.get("slo_list", []):
        metric_name = slo["metric"]
        start_time = int(time.time() - 86400 * lookback) * 1000
        op_lt = slo.get("operator", "").upper() == "LT"
        threshold = int(slo["threshold"])
        resource_type = slo["resourceType"]
        slo_name = slo["name"]
        interval = int(slo.get("interval", 5))
        rollup = slo.get("rollup")

        page = 0
        while True:
            resources = get_resources_by_name("VMWARE", resource_type, None, page)
            if not resources:
                break
            page += 1

            ids_to_names = {r["identifier"]: r["resourceKey"]["name"] for r in resources if "identifier" in r and "resourceKey" in r}

            metrics = get_metrics(list(ids_to_names.keys()), [metric_name], start_time, interval, rollup)
            if not metrics or "values" not in metrics:
                continue

            for metric_chunk in metrics.get("values", []):
                breaches = 0
                resource_id = metric_chunk.get("resourceId")
                name = ids_to_names.get(resource_id, resource_id)
                metric_list = metric_chunk.get("stat-list", {}).get("stat", [])

                for metric in metric_list:
                    timestamps = metric.get("timestamps", [])
                    data = metric.get("data", [])
                    if not timestamps or not data or len(timestamps) != len(data):
                        continue
                    first_ts = timestamps[0]
                    last_ts = timestamps[-1]
                    timespan = last_ts - first_ts
                    if timespan <= 0:
                        continue
                    for i, ts in enumerate(timestamps):
                        value = data[i]
                        if value is None:
                            continue
                        if (op_lt and value < threshold) or (not op_lt and value > threshold):
                            breaches += 1
                    total_intervals = timespan / 300000.0
                    attainment = 100.0 * (1.0 - (breaches / total_intervals)) if total_intervals > 0 else 0.0
                    print(f"{name},{slo_name},{attainment:.2f}")


if __name__ == "__main__":
    main()