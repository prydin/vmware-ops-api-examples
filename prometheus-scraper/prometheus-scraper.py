import argparse
import sys
import time
from re import split

from prometheus_client import start_http_server, Gauge, generate_latest, REGISTRY

from client import VRopsClient


# Parse arguments
parser = argparse.ArgumentParser(
    prog='getmetric',
    description='Returns the latest value of a specified metric',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument("-k", '--adapterkind', required=False, default="VMWARE")
parser.add_argument('-r', '--resourcekind', required=True)
parser.add_argument('-m', '--metrics', required=True)

args = parser.parse_args()

# Create a client connection
client = VRopsClient(f"https://{args.host}", args.user, args.password, args.authsource)

# Create gauges
metrics = args.metrics.split(",")
gauges = {}
for metric in metrics:
    gauges[metric] = Gauge(metric, labelnames=["adapter_kind", "resource_kind", "resource_name"], documentation=metric)


try:
    #Serve metrics
    start_http_server(8888)
    while True:
        # Look up the resource by name and get the resource ID
        resources = client.get_resources(args.adapterkind, args.resourcekind, 0, 1000)
        resource_ids = list(map(lambda r: r["identifier"], resources))
        metric_result = client.get_latest_metrics(resource_ids, metrics)["values"]
        for resource_metrics in metric_result:
            for stat in resource_metrics["stat-list"]["stat"]:
                stat_key = stat["statKey"]["key"]
                timestamps = stat["timestamps"]
                data = stat["data"]
                for i in range(len(stat["timestamps"])):
                    print(stat_key, timestamps[i], data[i])
        time.sleep(300)
except Exception as e:
    print(f"Error exposing metrics: {e}")
