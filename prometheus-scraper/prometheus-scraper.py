import argparse
import sys
import time
from email.policy import default
from re import split

import yaml
from prometheus_client import start_http_server, Gauge

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
parser.add_argument('-P', '--port', required=False, default='8888')
parser.add_argument("-c", "--config", required=False, default="./config.yaml")


args = parser.parse_args()

# Load configuration
with open(args.config, "r") as config_file:
    config = yaml.safe_load(config_file)

# Create a client connection
client = VRopsClient(f"https://{args.host}", args.user, args.password, args.authsource)

# Create gauges

try:
    #Serve metrics
    start_http_server(int(args.port))
    gauges = {}
    while True:
        # Look up the resource by name and get the resource ID
        start_time = time.time()
        print("Starting collection")
        for config_section in config:
            page = 0

            metrics = config_section["metrics"]
            for metric in metrics:
                metric = metric.replace("|", "_")
                if metric in gauges:
                    continue
                gauges[metric] = Gauge(metric, labelnames=["adapter_kind", "resource_kind", "resource_name"],
                                       documentation=metric)
            while True:
                resources = client.query_resources(config_section["resourceQuery"], page,1000)
                page += 1
                print(f"Found {len(resources)} resources")
                if len(resources) == 0:
                    break
                resource_ids = list(map(lambda r: r["identifier"], resources))
                resource_names = {}
                resource_kinds = {}
                adapter_kinds = {}
                for r in resources:
                    resource_names[r["identifier"]] = r["resourceKey"]["name"]
                    resource_kinds[r["identifier"]] = r["resourceKey"]["resourceKindKey"]
                    adapter_kinds[r["identifier"]] = r["resourceKey"]["adapterKindKey"]
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
                            gauge.labels(resource_name=resource_name, resource_kind=resource_kinds[resource_id],
                                         adapter_kind=adapter_kinds[resource_id]).set(data[i])
        print(f"Collection took {time.time() - start_time}s")
        time.sleep(300)
except Exception as e:
    print(f"Error exposing metrics: {e}")
