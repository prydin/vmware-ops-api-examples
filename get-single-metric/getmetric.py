import argparse
import sys

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
parser.add_argument('-n', '--resourcename', required=True)
parser.add_argument('-m', '--metric', required=True)
parser.add_argument('-U', '--unit', required=False, default=None)

args = parser.parse_args()

# Create a client connection
client = VRopsClient(f"https://{args.host}", args.user, args.password, args.authsource)


# Look up the resource by name and get the resource ID
r = client.get_resource_by_name(args.adapterkind, args.resourcekind, args.resourcename)
id = r["identifier"]

# Look up the metric key based on the display name
key = client.get_metric_key_by_display_name(args.adapterkind, args.resourcekind, args.metric, args.unit)

# Get and unpack the latest metric
metrics = client.get_latest_metrics(id, [key])
values = metrics["values"]
if len(values) == 0:
    print("No metrics found")
    sys.exit(1)
stats = values[0]["stat-list"]["stat"]
if len(stats) == 0:
    print("No metrics found")
    sys.exit(1)
data = stats[0]["data"]
if len(data) == 0:
    print("No metrics found")
    sys.exit(1)
print(data[0])



