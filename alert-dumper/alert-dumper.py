import argparse
import csv
import ssl
import re
import json
import sys
from functools import lru_cache
from urllib.error import URLError, HTTPError
from urllib import request

PAGESIZE = 10000

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


def get_all_alert_definitions():
    definitions = []
    page = 0
    while True:
        uri = f"/api/alertdefinitions?pageSize={PAGESIZE}&page={page}"
        response = get(uri)
        definitions.extend(response.get("alertDefinitions", []))
        if len(response.get("alertDefinitions", [])) < PAGESIZE:
            break
        page += 1
    return definitions


def get_all_alert_types():
    types = []
    page = 0
    while True:
        uri = f"/api/alerts/types?pageSize={PAGESIZE}&page={page}"
        response = get(uri)
        types.extend(response.get("alertTypes", []))
        if len(response.get("alertTypes", [])) < PAGESIZE:
            break
        page += 1
    return types


@lru_cache(maxsize=10000)
def get_symptom_definition(symptom_id):
    uri = f"/api/symptomdefinitions?id={symptom_id}"
    response = get(uri)
    return response.get("symptomDefinitions", [])[0]


def get_all_symptom_definitions():
    uri = f"/api/symptomdefinitions?pageSize={PAGESIZE}"
    response = get(uri)
    return response.get("symptomDefinitions", [])


def dump(file, args):
    raw_types = get_all_alert_types()
    symptom_definitions = get_all_symptom_definitions()
    symptom_name_map = {s.get("id"): s.get("name") for s in symptom_definitions}
    alert_types = {}
    for atype in raw_types:
        alert_types[atype.get("id")] = atype.get("name")
        for stype in atype.get("subTypes", []):
            alert_types[stype.get("id")] = stype.get("name")
    csvfile = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
    if args.symptoms:
        for symptom in symptom_definitions:
            state = symptom.get("state")
            condition = state.get("condition")

            if condition and condition["type"] in ["CONDITION_HT", "CONDITION_PROPERTY_STRING", "CONDITION_PROPERTY_NUMERIC"]:
                key = condition["key"]
                operator = condition["operator"]
                value = condition["value"] if "value" in condition else condition["stringValue"]
            elif condition and condition["type"] == "CONDITION_MESSAGE_EVENT":
                key = condition["eventType"]
                value = condition["message"]
                operator = condition["operator"]
            elif condition and condition["type"] == "CONDITION_FAULT":
                key = condition["faultKey"]
                operator = ""
                value = ";".join(condition.get("faultEvents", []))
            elif condition and condition["type"] == "CONDITION_DT":
                key = condition["key"]
                operator = condition["operator"]
                value = ""
            else:
                key = ""
                operator = ""
                value = ""
            csvfile.writerow([symptom["name"], state["severity"], symptom["adapterKindKey"],
                              symptom["resourceKindKey"], key, operator, value])
    else:
        alerts = get_all_alert_definitions()
        for alert in alerts:
            impact_detail = alert["impact"].get("detail") if alert.get("impact") else ""

            # Collect symptoms details
            symptom_list = []
            symptom_ids = []
            for state in alert.get("states", []):
                symptoms = state.get("base-symptom-set")
                if symptoms:
                    if symptoms["type"] == "SYMPTOM_SET":
                        symptom_ids += symptoms.get("symptomDefinitionIds", [])
                    else:
                        for ss in symptoms.get("symptom-sets", []):
                            symptom_ids += ss.get("symptomDefinitionIds", [])
            for s in symptom_ids:
                if s[0] == "!":
                    s = s[1:]
                    symptom_name = "NOT " + symptom_name_map.get(s, "")
                else:
                    symptom_name = symptom_name_map.get(s, "")
                symptom_list.append(symptom_name)

            csvfile.writerow([alert.get("name"), alert.get("adapterKindKey"),
                              alert["resourceKindKey"], alert_types.get(alert["type"]), alert_types
                             .get(alert.get("subType")), alert["states"][0].get("severity"), impact_detail,
                              alert.get("waitCycles"), alert.get("cancelCycles"), ";".join(symptom_list)
                              ])


def main():
    """
    Main function to build relationships between resources based on properties.
    """
    parser = argparse.ArgumentParser(prog="alert-dumper",
                                     description="Dumps alert defitions or symptom definitions from VCF Ops in CSV format")
    parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
    parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
    parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
    parser.add_argument("-a", "--authsource", required=False,
                        help="The VCF Ops authentication source. Default is Local")
    parser.add_argument("-s", "--symptoms", required=False, action="store_true",
                        help="If set, dump symptoms instead of alerts")
    parser.add_argument("-o", "--output", required=False, help="Output file")
    parser.add_argument("-U", "--unsafe", required=False, action="store_true",
                        help="Skip certificate checking (this is unsafe!)")

    args = parser.parse_args()

    if args.unsafe:
        # Unsafe: accept self-signed certificates
        ssl_context = ssl._create_unverified_context()
        globals()["ssl_context"] = ssl_context

    try:
        login(args.host, args.user, args.password, args.authsource)
    except URLError as e:
        if "certificate" in str(e).lower():
            sys.stderr.write(
                "The server appears to have a self-signed certificate. Override by adding the --unsafe option (not recommended in production)\n")
            sys.exit(1)
        else:
            raise

    if args.output:
        with open(args.output, "w", encoding='utf-8') as f:
            dump(f, args)
    else:
        dump(sys.stdout, args)
if __name__ == "__main__":
    main()
