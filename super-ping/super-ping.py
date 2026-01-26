import argparse
import re
import ssl
import socket
import sys
import time
import threading
import queue
from ipaddress import IPv4Address
from multiprocessing.managers import Value
from sys import stderr

import requests
import urllib.request as request
from urllib.error import HTTPError, URLError
import json
import urllib3
import yaml
from math import floor
import OpenSSL
from datetime import datetime
import platform
import subprocess
import icmplib
import ipaddress


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAGESIZE=1000

url_base = ""
headers = {"Accept": "application/json", "Content-Type": "application/json"}

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


def get_resources_by_name(adapter_kind, resource_kind, name, page=0):
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


def get_related_resources(adapter_kind, resource_kind, rel_type, rel_name, page=0):
    payload = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "propertyName": "summary|parent" + rel_type[0].upper() + rel_type[1:],
        "propertyValue": rel_name
    }
    resource_response = post(f"/api/resources/query?page={page}&pageSize={PAGESIZE}", payload)
    return resource_response.get("resourceList", [])


def get_resource_by_name(adapter_kind, resource_kind, name):
    resources = get_resources_by_name(adapter_kind, resource_kind, name)
    if len(resources) == 0:
        return None
    if len(resources) > 1:
        raise Exception("More than one resource matched")
    return resources[0]

def get_all_properties(resource_id):
    return get(f"/api/resources/{resource_id}/properties")

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



def run_worker(input_queue, output_queue):
    while True:
        try:
            task = input_queue.get()
            if task is None:
                break
            func, args = task
            result = func(*args)
            output_queue.put(result)
        except Exception as e:
            print(e)
        finally:
            input_queue.task_done()
    input_queue.join()
    output_queue.put(None)

def get_certificate(host, port=443, timeout=10):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = socket.create_connection((host, port), timeout=timeout)
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


def get_cert_metrics(host, port=443, timeout=10):
    try:
        certificate = get_certificate(host)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

        days_left = floor((datetime.strptime(x509.get_notAfter().decode(), '%Y%m%d%H%M%SZ').timestamp() - time.time()) / 86400)
        subject = ""
        for part in x509.get_subject().get_components():
            subject += "/" + part[0].decode() + "=" + part[1].decode()

        return {
            "type": "SuperPingCert",
            "$subject": subject,
            "success": 1,
            "address": host,
            "days_left": days_left
        }
    except Exception as e:
        print(e)
        return {
            "type": "SuperPingCert",
            "address": host,
            "success": 0,
        }

def ping_url(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout, verify=False)
        return {
            "type": "SuperPingURL",
            "address": url,
            "success": 1,
            "status_code": response.status_code,
            "response_time_ms": response.elapsed.total_seconds() * 1000
        }
    except requests.exceptions.RequestException as e:
        return {
            "type": "SuperPingURL",
            "address": url,
            "success": 0,
            "status_code": e.response.status_code if e.response else None
        }

def ping_tcp(host, port=443, timeout=10):
    start_time = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            end_time = time.time()
            return {
                "type": "SuperPingTCP",
                "address": host,
                "success": 1,
                "response_time_ms": (end_time - start_time) * 1000
            }
    except socket.error as e:
        return {
            "type": "SuperPingTCP",
            "address": host,
            "success": 0
        }


def ping_icmp(host, timeout=10):
    try:
        result = icmplib.ping(host, count=1, timeout=timeout, privileged=False)
        if result.packet_loss == 0:
            return {
                "type": "SuperPingICMP",
                "address": host,
                "success": 1,
                "response_time_ms": result.avg_rtt
            }
        else:
            return {
                "type": "SuperPingICMP",
                "address": host,
                "success": 0
            }
    except Exception as e:
        return {
            "type": "SuperPingICMP",
            "address": host,
            "success": 0,
        }


# Parse arguments
parser = argparse.ArgumentParser(
    prog='super-ping',
    description='Multi-protocol ping utility',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=False)
parser.add_argument('-P', '--passwordfile', required=False)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument("-c", "--config", required=False, default="./config.yaml")
parser.add_argument("-t", "--threads", required=False, default="10")
parser.add_argument("-U", "--unsafe", required=False, action="store_true",
                    help="Skip certificate checking (this is unsafe!)")
args = parser.parse_args()

if (not args.password and not args.passwordfile) or (args.password and args.passwordfile):
    stderr.write("Either password or password file must be specified (mutially exclusive)\n")
    sys.exit(1)

if args.unsafe:
    # Unsafe: accept self-signed certificates
    ssl_context = ssl._create_unverified_context()
    globals()["ssl_context"] = ssl_context

num_threads = int(args.threads)

if args.passwordfile:
    with open(args.passwordfile, "r") as f:
        args.password = f.read().strip()

try:
    login(args.host, args.user, args.password, args.authsource)
except URLError as e:
    if "certificate" in str(e).lower():
        sys.stderr.write("The server appears to have a self-signed certificate. Override by adding the --unsafe option (not recommended in production)\n")
        sys.exit(1)
    else:
        raise

# Load configuration
# We're simply loading the resource query from the config file. This makes the code
# simple and allows arbitrarily complex queries to be defined.
with open(args.config, "r") as config_file:
    config = yaml.safe_load(config_file)

# Prepare pinger threads
input_queue = queue.Queue()
output_queue = queue.Queue()
for i in range(num_threads):
    t = threading.Thread(target=run_worker, args=(input_queue, output_queue))
    t.daemon = True
    t.start()

ip_to_vm = {}
for target in config.get("targets", []):
    timeout = target.get("timeout", 10)
    if target["type"] == "icmp":
        for address in target.get("addresses", []):
            input_queue.put((ping_icmp, (address, timeout)))
    elif target["type"] == "tcp":
        for address in target.get("addresses", []):
            input_queue.put((ping_tcp, (address, target.get("port", 443), timeout)))
    elif target["type"] == "cert":
        for address in target.get("addresses", []):
            input_queue.put((get_cert_metrics, (address, target.get("port", 443), timeout)))
    elif target["type"] == "url":
        for address in target.get("addresses", []):
            input_queue.put((ping_url, (address, timeout)))
    elif target["type"] == "vms":
        exclude_ips = target.get("excludeIps", [])
        for excluded_ip in exclude_ips:
            network = ipaddress.ip_network(excluded_ip)
        resources = get_related_resources("VMWARE", "VirtualMachine", target["parentType"], target["parentName"])
        for r in resources:
            all_props = get_all_properties(r["identifier"])
            for prop in all_props.get("property", []):
                if re.match(r"net:[0-9]+\|ip_address", prop.get("name")):
                    ip_address = prop.get("value")
                    if ip_address:
                        try:
                            if IPv4Address(ip_address) not in exclude_ips:
                                input_queue.put((ping_icmp, (ip_address, timeout)))
                                ip_to_vm[ip_address] = r["identifier"]
                        except ValueError:
                            # Not an IP address
                            pass


# Put enough end tokens in the queue for the workers to exit
for i in range(num_threads):
    input_queue.put(None)
while True:
    result = output_queue.get()
    if result is None:
        break
    resource_type = result.get("type")
    address = result.get("address")

    # Check if we already have the resource
    r = get_resource_by_name("SuperPingAdapter", resource_type, address)
    if r:
        res_id = r["identifier"]
    else:
        # Create the resource if it didn't exist
        res_payload = {
            "resourceKey": {
                "name": address,
                "adapterKindKey": "SuperPingAdapter",
                "resourceKindKey": resource_type
            },
            "properties": {
                "address": address
            }
        }
        r = post(f"/api/resources/adapterkinds/SuperPingAdapter", res_payload)
        res_id = r["identifier"]

    # Deal with metrics
    stat_list = []
    for metric, value in result.items():
        if metric == "type" or metric == "address" or metric.startswith("$"):
            continue
    #    print(f"superping.{resource_type}.{metric} {value}", address, res_id)
        stat_list.append({
            "statKey": metric,
            "timestamps": [int(time.time() * 1000)],
            "values": [value]
        })

    payload = {
        "resource-stat-content": [{
            "id": res_id,
            "stat-contents": stat_list,
        }]
    }
    print(f"Posted {len(result)-2} metrics for {address} ({resource_type})")
    post("/api/resources/stats", payload)

    # Deal with properties
    props = []
    for prop, value in result.items():
        if prop.startswith("$"):
            props.append({
                    "statKey": prop[1:],
                    "timestamps": [int(time.time()) * 1000],
                    "values": [value]
                })
    if len(props) > 0:
        prop_payload = {
            "property-content": props
        }
        post(f"/api/resources/{res_id}/properties", prop_payload)

    # Add relation to VM if applicable
    if address in ip_to_vm:
        vm_id = ip_to_vm[address]
        add_relation(res_id, vm_id, "PARENT")
