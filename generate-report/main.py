import json
import os.path
import sys
from time import sleep
from urllib.parse import urlencode

from setuptools.command.setopt import config_file

sys.path.append("../common")

from client import VRopsClient

# Create connection and authenticate
with open(os.path.expanduser("~/ariatest.json"), "r") as config_file:
    config = json.load(config_file)
client = VRopsClient(config["url"], config["username"], config["password"])

# To run a report, we need to find report definition as well as the root resource to run the report against.
# Start by finding the resource. In this case, we'll use a Datacenter as the root resource
resources = client.get_resources("VMWARE", "Datacenter", "vcfcons-mgmt-dc01")
resource_id = resources[0]["identifier"]

# Next, we look up the report definition
report_query = {"name": "Demo Cluster Capacity" }
reports = client.get(f"/api/reportdefinitions?{urlencode(report_query)}")
report_definition_id = reports["reportDefinitions"][0]["id"]

# Run the report. Create a report request and issue a POST HTTP call
report_spec = {
    "reportDefinitionId": report_definition_id,
    "resourceId": resource_id
}
report_run = client.post("/api/reports", report_spec)

# Grab the ID of the run so we can check it it's completed.
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