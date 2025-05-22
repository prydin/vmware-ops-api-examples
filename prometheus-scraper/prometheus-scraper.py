import argparse
import sys
import time
from re import split

from prometheus_client import start_http_server, Gauge, generate_latest, REGISTRY

from client import VRopsClient


# Parse arguments
parser = argparse.ArgumentParser(
    prog='prometheus-scraper',
    description='A very simple Prometheus scraper for getting metrics from VCF Ops',
)
parser.add_argument('-H', '--host', required=True)
parser.add_argument('-u', '--user', required=True)
parser.add_argument('-p', '--password', required=True)
parser.add_argument("-a", '--authsource', required=False)
parser.add_argument("-k", '--adapterkind', required=False, default="VMWARE")
parser.add_argument('-r', '--resourcekind', required=True)
parser.add_argument('-m', '--metrics', required=True)
parser.add_argument('-P', '--port', required=False, default='8888')


args = parser.parse_args()

# Create a client connection
client = VRopsClient(f"https://{args.host}", args.user, args.password, args.authsource)

# Create gauges
metrics = args.metrics.split(",")
gauges = {}
for metric in metrics:
    metric = metric.replace("|", "_")
    gauges[metric] = Gauge(metric, labelnames=["adapter_kind", "resource_kind", "resource_name"], documentation=metric)


try:
    #Serve metrics
    start_http_server(int(args.port))
    while True:
        # Look up the resource by name and get the resource ID
        resources = client.get_resources(args.adapterkind, args.resourcekind, 0, 1000)
        resource_ids = list(map(lambda r: r["identifier"], resources))
        resource_names = {}
        for r in resources:
            resource_names[r["identifier"]] = r["resourceKey"]["name"]
        metric_result = client.get_latest_metrics(resource_ids, metrics)["values"]
        for resource_metrics in metric_result:
            resource_id = resource_metrics["resourceId"]
            resource_name = resource_names.get(resource_id, "-unknown-")
            for stat in resource_metrics["stat-list"]["stat"]:
                stat_key = stat["statKey"]["key"].replace("|", "_")
                timestamps = stat["timestamps"]
                data = stat["data"]
                gauge = gauges.get(stat_key, None)
                if not gauge:
                    continue
                for i in range(len(stat["timestamps"])):
                    print(resource_name, stat_key, timestamps[i], data[i])
                    # vrops_metric.labels(vm_name=vm_name, resource_id=vm_id).set(1 if power_state == "POWERED_ON" else 0)
                    gauge.labels(resource_name=resource_name, resource_kind=args.resourcekind, adapter_kind=args.adapterkind).set(data[i])
        time.sleep(300)
except Exception as e:
    print(f"Error exposing metrics: {e}")
