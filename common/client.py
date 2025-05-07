from functools import cache
from time import time

import requests
import json
import urllib3
from functools import lru_cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAGESIZE = 1000

"""
Convenience class for interacting with Aria Ops
"""
class VRopsClient:
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-Ops-API-use-unsupported": "true"}

    url_base = ""

    token = ""

    """
    Creates a new client object.
    
    Parameters
    ----------
    url_base : str 
        The base portion of the Aria Ops instance url, e.g. https://example.com
    username : str
        Username for authentication
    password : str
        Password for authentication
    auth_source : str
        Authentication source as displayed in the login dialog    
    """
    def __init__(self, url_base, username=None, password=None, auth_source=None):
        # Validate password. This will return a token that can be used
        # throughout the session.
        self.url_base = url_base + "/suite-api"
        cred_payload = {"username": username, "password": password}
        if auth_source:
            cred_payload["authSource"] = auth_source;
        credentials = json.dumps(cred_payload)
        result = requests.post(url=self.url_base + "/api/auth/token/acquire",
                               data=credentials,
                               verify=False, headers=self.headers)
        if result.status_code != 200:
            print(str(result.status_code) + " " + str(result.content))
            exit(1)
        json_data = json.loads(result.content)
        token = json_data["token"]
        self.headers["Authorization"] = "vRealizeOpsToken " + token

    """
    Executes a GET request against an api and treats the response as JSON
    
    Parameters
    uri : str
        The leaf portion of the URL, e.g. "/api/resources
    """
    def get(self, uri):
        response = requests.get(url=self.url_base + uri,
                                headers=self.headers,
                                verify=False)
        if response.status_code != 200:
            raise Exception("HTTP Status: %d, details: %s" % (response.status_code, response.content))
        return response.json()

    """
    Executes a GET request against an api and treats the response as raw bytes

    Parameters
    uri : str
        The leaf portion of the URL, e.g. "/api/resources
    """

    def get_raw(self, uri):
        response = requests.get(url=self.url_base + uri,
                                headers=self.headers,
                                verify=False)
        if response.status_code != 200:
            raise Exception("HTTP Status: %d, details: %s" % (response.status_code, response.content))
        return response.content

    """
    Executes a POST request against an api

    Parameters
    ----------
    uri : str
        The leaf portion of the URL, e.g. "/api/resources
    data : The payload for the body. Can be anything that's JSON serializable
    
    Returns 
    -------
    obj 
        An object holding the deserialized content of the response
    """
    def post(self, url, data):
        response = requests.post(url=self.url_base + url,
                                 headers=self.headers,
                                 verify=False,
                                 json=data)
        if response.status_code != 200:
            raise Exception("HTTP Status: %d, details: %s" % (response.status_code, response.content))
        return response.json()

    """
    Finds a resource based on its adapter kind, resource kind and name.
    
    Paremeters
    ----------
    adapter_kind : str
        The adapter kind of the resource, e.g. "VMWARE"
    resource_kind
        The resource kind of the resource, e.g. "VirtualMachine"
    name:
        The name of the resource, e.g. "reporting-server-01"
        
    Returns
    =======
    obj 
        An object representing the resource
    """
    def get_resource_by_name(self, adapter_kind, resource_kind, name):
        payload = {
            "adapterKind": [adapter_kind],
            "resourceKind": [resource_kind],
            "name": [name]
        }
        resource_response = self.post("/api/resources/query", payload)
        resource_list = resource_response["resourceList"]
        if len(resource_list) == 0:
            raise Exception("No matching resources found")
        if len(resource_list) > 1:
            raise Exception("More than one resource matched")
        return resource_list[0]

    """
    Gets all resources of a specified kind
    
    Parameters
    ----------
    adapter_kind : str
        The adapter kind of the resource, e.g. "VMWARE"
    resource_kind : str
        The resource kind of the resource, e.g. "VirtualMachine"
    page : int, optional
       The page number (default: 0)
    pagesize : int, optional
        Number of resources per page (default: 1000)
    """
    def get_resources(self, adapter_kind, resource_kind, page = 0, pagesize = 1000):
        payload = {
            "adapterKind": [adapter_kind],
            "resourceKind": [resource_kind]
        }
        return self.post(f"/api/resources/query?page={page}&pageSize={pagesize}", payload)["resourceList"]

    """
    Returns the metrics for a resource
    
    Parameters
    ----------
    resource_id : str
        The ID of the resource to request metrics from
    metric_keys : list
        A list of metric keys
    rollup_type : str
        Specifies how to aggregate the metrics within an interval. Valid values are "AVG", "MIN", "MAX", "LATEST",
        "COUNT". Default is "LATEST".
    interval_seconds : str
        Number of seconds per rollup interval. Maximum resolution is 1 minute.
    start : int
        Start time as UNIX time.
    end : int
        End time as UNIX time.
    
    """
    def get_metrics(self, resource_id, metric_keys, rollup_type="LATEST", interval_seconds=300, start=None, end=None):
        begin = start if start else (time() - 300) * 1000
        payload = {
            "resourceId": [resource_id],
            "statKey": metric_keys,
            "rollUpType": rollup_type,
            "intervalType": "MINUTES",
            "intervalQuantifier": int(interval_seconds / 60),
            "begin": int(begin),
        }
        if end:
            payload["end"] = end
        return self.post("/api/resources/stats/query", payload)

    """
    Returns the latest metrics for a resource

    Parameters
    ----------
    resource_id : str
        The ID of the resource to request metrics from
    metric_keys : list
        A list of metric keys
    """
    def get_latest_metrics(self, resource_id, metric_keys):
        payload = {
            "resourceId": [resource_id],
            "statKey": metric_keys
        }
        return self.post("/api/resources/stats/query", payload)

    """
    Returns the value of the specified properties of a specific resource
    
    Parameters
    ----------
    resource_id : str
        The id of the resource to query
    prop_keys : array [str]
        The properties to query
        
    Returns
    -------
    An object holding the property values.
    """
    def get_properties(self, resource_id, prop_keys):
        payload = {
            "resourceIds": [resource_id],
            "propertyKeys": prop_keys
        }
        values = self.post("/api/resources/properties/latest/query", payload)["values"]
        return values[0] if len(values) > 0 else None

    """
    Returns the property keys of a specific resource
    
    Parameters
    ----------
    resource_id : str
        The resource id to query
        
    Returns
    -------
    An object holding the metric keys
    """
    def get_metric_keys(self, resource_id):
        values = self.get(f"/api/resources/{resource_id}/statkeys")["stat-key"]
        return map(lambda k: k["key"], values)

    """
    Gets a the metric key of a resource kind based on the display name
    
    Parametere
    ----------
    adapter_kind : str
        The adapter kind for the resource
    resource_kind : str
        The resource kind
    display_name : str 
        The display name of a metric key (without unit)
    unit : str, optional
        The unit of the metric if needed to uniquely idenfify the metric e.g. "CPU|Demand (MHz)" vs "CPU|Demand (%)"
        
    Returns
    -------
    The metric key
    """
    @lru_cache(maxsize=1000)
    def get_metric_key_by_display_name(self, adapter_kind, resource_kind, display_name, unit=None):
        values = self.get(f"/api/adapterkinds/{adapter_kind}/resourcekinds/{resource_kind}/statkeys?pageSize=10000")["resourceTypeAttributes"]
        matches = list(filter(lambda v: v["name"] == display_name, values))
        if unit:
            matches = list(filter(lambda m: m["unit"] == unit, matches))
        if len(matches) == 0:
            raise Exception("Metric key not found")
        if len(matches) > 1:
            raise Exception("Multiple matches found")
        return matches[0]["key"]
