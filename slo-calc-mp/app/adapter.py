#  Copyright 2022 VMware, Inc.
#  SPDX-License-Identifier: Apache-2.0
import json
import sys
import time
from email.policy import default
from typing import List

import aria.ops.adapter_logging as logging
import psutil
from aria.ops.adapter_instance import AdapterInstance
from aria.ops.data import Metric
from aria.ops.data import Property
from aria.ops.definition.adapter_definition import AdapterDefinition
from aria.ops.definition.units import Units
from aria.ops.result import CollectResult
from aria.ops.result import EndpointResult
from aria.ops.result import TestResult
from aria.ops.timer import Timer
from constants import ADAPTER_KIND
from constants import ADAPTER_NAME

logger = logging.getLogger(__name__)

MAX_SLOS = 5

def get_adapter_definition() -> AdapterDefinition:
    """
    The adapter definition defines the object types and attribute types (metric/property) that are present
    in a collection. Setting these object types and attribute types helps VMware Aria Operations to
    validate, process, and display the data correctly.
    :return: AdapterDefinition
    """
    with Timer(logger, "Get Adapter Definition"):
        try:
            definition = AdapterDefinition(ADAPTER_KIND, ADAPTER_NAME)
            for i in range(1, MAX_SLOS + 1):
                definition.define_string_parameter(
                    key=f"sloName{i}",
                    label="SLO Name",
                    description="SLO Name",
                    required=i == 1,
                )

                definition.define_string_parameter(
                    key=f"sloResourceType{i}",
                    label="SLO Resource Type",
                    description="Resource type the SLO will act on",
                    required=i == 1,
                )

                definition.define_string_parameter(
                    key=f"sloMetric{i}",
                    label="SLO Metric",
                    description="Metric the SLO will act on",
                    required=i == 1,
                )

                definition.define_int_parameter(
                    key=f"sloThreshold{i}",
                    label="SLO Threshold",
                    description="Threshold value for the SLO",
                    required=i == 1,
                )

                definition.define_enum_parameter(
                    key=f"sloCondition{i}",
                    label="SLO Condition",
                    description="Condition for the SLO threshold (Above/Below)",
                    required=i == 1,
                    values=["Above", "Below"],
                    default="Above",
                )

                definition.define_int_parameter(
                    f"sloLookbackPeriod{i}",
                    label="SLO Lookback Period (Days)",
                    description="Number of days to look back when calculating SLO attainment",
                    required=i == 1,
                    default=30,
                )

                definition.define_int_parameter(
                    f"rollupInterval{i}",
                    label="SLO Rollup Interval (Minutes)",
                    description="Interval in minutes at which to roll up the SLO",
                    required=i == 1,
                    default=5,
                )

                definition.define_enum_parameter(
                    key=f"sloRollupType{i}",
                    label="SLO Rollup Type",
                    description="Type of rollup to perform for the SLO",
                    values=["AVG", "MIN", "MAX", "SUM"],
                    default="AVG",
                    required=i == 1,
                )

            # The key 'container_memory_limit' is a special key that is read by the VMware Aria Operations collector to
            # determine how much memory to allocate to the docker container running this adapter. It does not
            # need to be read inside the adapter code.
            definition.define_int_parameter(
                "container_memory_limit",
                label="Adapter Memory Limit (MB)",
                description="Sets the maximum amount of memory VMware Aria Operations can "
                "allocate to the container running this adapter instance.",
                required=True,
                advanced=True,
                default=1024,
            )

            slo = definition.define_object_type("SLO", "SLO")
            slo.define_metric("score", "SLO Attainment Score", Units.TIME.SECONDS)
            slo.define_string_property("resourceType", "Resource Type")
            slo.define_string_property("metricName", "Metric Name")

            slo_attainment = definition.define_object_type("SLOAttainment", "SLO Attainment")
            slo_attainment.define_string_property("resourceName", "Resource Name")
            slo_attainment.define_metric("score", "SLO Score", Units.RATIO.PERCENT)
            logger.debug(f"Returning adapter definition: {definition.to_json()}")
            return definition
        except Exception as e:
            logger.error("Unexpected adapter definition error")
            logger.exception(e)
            raise


def test(adapter_instance: AdapterInstance) -> TestResult:
    with Timer(logger, "Test"):
        result = TestResult()
        try:
            pass # TODO: Implement connection test code here
        except Exception as e:
            logger.error("Unexpected connection test error")
            logger.exception(e)
            result.with_error("Unexpected connection test error: " + repr(e))
        finally:
            # TODO: If any connections are still open, make sure they are closed before returning
            logger.debug(f"Returning test result: {result.get_json()}")
            return result


def collect(adapter_instance: AdapterInstance) -> CollectResult:
    logger.debug("Starting collection")
    with Timer(logger, "Collection"):
        try:
            ops_client = adapter_instance.suite_api_client
            ops_client.get_token()
            result = CollectResult()
            for i in range(1, MAX_SLOS + 1):
                slo_name = adapter_instance.get_identifier_value(f"sloName{i}")
                logger.debug(f"Processing SLO {i}: {slo_name}")
                if not slo_name:
                    continue  # No more SLOs configured

                threshold = float(adapter_instance.get_identifier_value(f"sloThreshold{i}"))
                resource_type = adapter_instance.get_identifier_value(f"sloResourceType{i}")
                metric_name = adapter_instance.get_identifier_value(f"sloMetric{i}")
                lookback = int(adapter_instance.get_identifier_value(f"sloLookbackPeriod{i}"))
                condition = adapter_instance.get_identifier_value(f"sloCondition{i}")
                rollup = adapter_instance.get_identifier_value(f"sloRollupType{i}")
                interval = int(adapter_instance.get_identifier_value(f"rollupInterval{i}"))
                if not slo_name:
                    continue  # No more SLOs configured

                # Create SLO resource
                slo = result.object(ADAPTER_KIND, "SLO", f"{slo_name}")
                resource_type_property = Property("resourceType", resource_type)
                metric_name_property = Property("metricName", metric_name)
                slo.add_property(resource_type_property)
                slo.add_property(metric_name_property)

                op_below = condition.upper() == "BELOW"
                start_time = int(time.time() - 86400 * lookback) * 1000

                # Query for resources of the specified type
                query = {
                    "adapterKind": ["VMWARE"],
                    "resourceKind": [resource_type],
                }
                logger.debug("Querying for resources: %s", json.dumps(query))
                with ops_client.post("/api/resources/query", json=query) as response:
                    if response.status_code != 200:
                        logger.error(f"Failed to query resources: {response.status_code} {response.text}")
                        continue
                    resources = response.json().get("resourceList", [])
                if len(resources) == 0:
                    logger.warning(f"No resources found for type {resource_type}")
                    continue # TODO: Pagination if needed
                ids_to_names = {r["identifier"]: r["resourceKey"]["name"] for r in resources if
                                "identifier" in r and "resourceKey" in r}
                logger.debug(f"Found {len(ids_to_names)} resources of type {resource_type}")

                # TODO: Implement pagination if needed
                query = {
                    "resourceId": list(ids_to_names.keys()),
                    "statKey": [metric_name],
                    "begin": start_time,
                    "rollUpType": rollup,
                    "intervalType": "MINUTES",
                    "intervalQuantifier": interval,
                }
                with ops_client.post("/api/resources/stats/query", json=query) as response:
                    if response.status_code != 200:
                        logger.error(f"Failed to retrieve metrics: {response.status_code} {response.text}")
                        continue
                    metrics = response.json()
                if not metrics or "values" not in metrics:
                    continue

                for metric_chunk in metrics.get("values", []):
                    resource_id = metric_chunk.get("resourceId")
                    name = ids_to_names.get(resource_id, resource_id)
                    slo_attainment = result.object(ADAPTER_KIND, "SLOAttainment", f"{slo_name}/{name}")
                    slo.add_child(slo_attainment)

                    breaches = 0
                    metric_list = metric_chunk.get("stat-list", {}).get("stat", [])

                    for metric in metric_list:
                        timestamps = metric.get("timestamps", [])
                        data = metric.get("data", [])
                        if not timestamps or not data or len(timestamps) != len(data):
                            continue
                        first_ts = timestamps[0]
                        last_ts = timestamps[-1]
                        timespan = last_ts - first_ts
                        if timespan <= 0:
                            continue
                        for i, ts in enumerate(timestamps):
                            value = data[i]
                            if value is None:
                                continue
                            if (op_below and value < threshold) or (not op_below and value > threshold):
                                breaches += 1
                        total_intervals = timespan / 300000.0
                        attainment = 100.0 * (
                                    1.0 - (breaches / total_intervals)) if total_intervals > 0 else 0.0
                        logger.debug(f"{name},{slo_name},{attainment:.2f}")
                        slo_score = Metric("score", attainment)  # Replace with actual calculation
                        slo_attainment.add_metric(slo_score)

                    resource_name_property = Property("resourceName", name)
                    slo_attainment.add_property(resource_name_property)
        except Exception as e:
            logger.error("Unexpected collection error")
            logger.exception(e)
            result.with_error("Unexpected collection error: " + repr(e))
        finally:
            # TODO: If any connections are still open, make sure they are closed before returning
            logger.debug(f"Returning collection result {result.get_json()}")
            return result


def get_endpoints(adapter_instance: AdapterInstance) -> EndpointResult:
    with Timer(logger, "Get Endpoints"):
        result = EndpointResult()
        # In the case that an SSL Certificate is needed to communicate to the target,
        # add each URL that the adapter uses here. Often this will be derived from a
        # 'host' parameter in the adapter instance. In this Adapter we don't use any
        # HTTPS connections, so we won't add any. If we did, we might do something like
        # this:
        # result.with_endpoint(adapter_instance.get_identifier_value("host"))
        #
        # Multiple endpoints can be returned, like this:
        # result.with_endpoint(adapter_instance.get_identifier_value("primary_host"))
        # result.with_endpoint(adapter_instance.get_identifier_value("secondary_host"))
        #
        # This 'get_endpoints' method will be run before the 'test' method,
        # and VMware Aria Operations will use the results to extract a certificate from
        # each URL. If the certificate is not trusted by the VMware Aria Operations
        # Trust Store, the user will be prompted to either accept or reject the
        # certificate. If it is accepted, the certificate will be added to the
        # AdapterInstance object that is passed to the 'test' and 'collect' methods.
        # Any certificate that is encountered in those methods should then be validated
        # against the certificate(s) in the AdapterInstance.
        logger.debug(f"Returning endpoints: {result.get_json()}")
        return result


# Main entry point of the adapter. You should not need to modify anything below this line.
def main(argv: List[str]) -> None:
    logging.setup_logging("adapter.log")
    # Start a new log file by calling 'rotate'. By default, the last five calls will be
    # retained. If the logs are not manually rotated, the 'setup_logging' call should be
    # invoked with the 'max_size' parameter set to a reasonable value, e.g.,
    # 10_489_760 (10MB).
    logging.rotate()
    logger.info(f"Running adapter code with arguments: {argv}")
    if len(argv) != 3:
        # `inputfile` and `outputfile` are always automatically appended to the
        # argument list by the server
        logger.error("Arguments must be <method> <inputfile> <ouputfile>")
        sys.exit(1)

    method = argv[0]
    try:
        if method == "test":
            test(AdapterInstance.from_input()).send_results()
        elif method == "endpoint_urls":
            get_endpoints(AdapterInstance.from_input()).send_results()
        elif method == "collect":
            collect(AdapterInstance.from_input()).send_results()
        elif method == "adapter_definition":
            result = get_adapter_definition()
            if type(result) is AdapterDefinition:
                result.send_results()
            else:
                logger.info(
                    "get_adapter_definition method did not return an AdapterDefinition"
                )
                sys.exit(1)
        else:
            logger.error(f"Command {method} not found")
            sys.exit(1)
    finally:
        logger.info(Timer.graph())
        sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])
