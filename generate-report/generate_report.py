import argparse
import json
import os.path
import sys
from time import sleep
from urllib.parse import urlencode

from setuptools.command.setopt import config_file

sys.path.append("../common")

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
parser.add_argument('-R', '--reportname', required=True)

args = parser.parse_args()

# Create a client connection
client = VRopsClient(f"https://{args.host}", args.user, args.password, args.authsource)

# To run a report, we need to find report definition as well as the root resource to run the report against.
# Start by finding the resource. In this case, we'll use a Datacenter as the root resource
resources = client.get_resources(args.adapterkind, args.resourcekind, args.resourcename)
resource_id = resources[0]["identifier"]

# Next, we look up the report definition
report_query = {"name": args.reportname }
reports = client.get(f"/api/reportdefinitions?{urlencode(report_query)}")
report_definition_id = reports["reportDefinitions"][0]["id"]

# Run the report. Create a report request and issue a POST HTTP call
report_spec = {
    "reportDefinitionId": report_definition_id,
    "resourceId": resource_id
}
report_run = client.post("/api/reports", report_spec)

# Grab the ID of the run so we can check if it's completed.
run_id = report_run["id"]

# Check for completion
while True:
    report_run = client.get(f"/api/reports/{run_id}")
    if report_run["status"] == "COMPLETED":
        break
    sleep(10)

# The report completed. Now we can download its content. We need to specify the format as
# csv in the query string.
report_content = client.get_raw(f"/api/reports/{run_id}/download?format=csv").decode()

# We now have the report content as a string. Just print it to the console. A practical
# program would probably save it to a file.
print(report_content)