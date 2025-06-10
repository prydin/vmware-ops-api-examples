import argparse
from sys import stderr, stdout
import time
from os import write

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
parser.add_argument("-c", "--config", required=False, default="./config.yaml")


args = parser.parse_args()

# Load configuration
with open(args.config, "r") as config_file:
    config = yaml.safe_load(config_file)

# Create a client connection
client = VRopsClient(f"https://{args.host}", args.user, args.password, args.authsource)

# Create gauges

try:
    # Look up the resource by name and get the resource ID
    start_time = time.time()
    stderr.write("Starting collection\n")
    for config_section in config:
        page = 0

        metrics = config_section["metrics"]
        for metric in metrics:
            metric = metric.replace("|", "_")
        while True:
            resources = client.query_resources(config_section["resourceQuery"], page,1000)
            page += 1
            stderr.write(f"Found {len(resources)} resources\n")
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
                resource_kind = resource_kinds.get(resource_id, "-unknown-")
                adapter_kind = adapter_kinds.get(resource_id, "-unknown-")
                for stat in resource_metrics["stat-list"]["stat"]:
                    stat_key = stat["statKey"]["key"]
                    timestamps = stat["timestamps"]
                    data = stat["data"]
                    if "|" in stat_key[1:]:
                        pipe_pos = stat_key.index("|")
                        measurement = stat_key[:pipe_pos]
                        field = stat_key[pipe_pos+1:]
                    else:
                        measurement = "default"
                        field = stat_key
                    field = field.replace("|", "_")
                    values = stat["data"]
                    timestamps = stat["timestamps"]
                    for i in range(len(timestamps)):
                        out = f"{measurement},name={resource_name},resourceKind={resource_kind},adapterKind={adapter_kind} {field}={values[i]} {timestamps[i]*1000000}"
                        print(out)

    stderr.write( f"Collection took {time.time() - start_time}s\n")
except Exception as e:
    stderr.write(f"Error exposing metrics: {e}\n")
