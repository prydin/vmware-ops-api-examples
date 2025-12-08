#  Copyright 2022 VMware, Inc.
#  SPDX-License-Identifier: Apache-2.0
import json
import sys
import time
import datetime
from typing import List
from datetime import datetime

import aria.ops.adapter_logging as logging
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
PAGESIZE = 100

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
                    label=f"SLO Name {i}",
                    description=f"SLO Name",
                    required=i == 1,
                )

                definition.define_string_parameter(
                    key=f"sloResourceType{i}",
                    label=f"SLO Resource Type {i}",
                    description="Resource type the SLO will act on",
                    required=i == 1,
                )

                definition.define_string_parameter(
                    key=f"sloMetric{i}",
                    label=f"SLO Metric {i}",
                    description="Metric the SLO will act on",
                    required=i == 1,
                )

                definition.define_int_parameter(
                    key=f"sloThreshold{i}",
                    label=f"SLO Threshold {i}",
                    description="Threshold value for the SLO",
                    required=i == 1,
                )

                definition.define_enum_parameter(
                    key=f"sloCondition{i}",
                    label=f"SLO Condition {i}",
                    description="Condition for the SLO threshold (Above/Below)",
                    required=i == 1,
                    values=["Above", "Below"],
                    default="Above",
                )

                definition.define_enum_parameter(
                    key=f"sloType{i}",
                    label=f"SLO Type {i}",
                    description="Type of SLO (sliding, monthly, quarterly)",
                    required=i == 1,
                    values=["Sliding", "Monthly", "Quarterly"],
                    default="Sliding",
                )

                definition.define_int_parameter(
                    f"sloLookbackPeriod{i}",
                    label=f"SLO Lookback Period (Days) {i}",
                    description="Number of days to look back when calculating SLO attainment",
                    required=i == 1,
                    default=30,
                )

                definition.define_int_parameter(
                    f"rollupInterval{i}",
                    label=f"SLO Rollup Interval (Minutes) {i}",
                    description="Interval in minutes at which to roll up the SLO",
                    required=i == 1,
                    default=5,
                )

                definition.define_enum_parameter(
                    key=f"sloRollupType{i}",
                    label=f"SLO Rollup Type ",
                    description="Type of rollup to perform for the SLO",
                    values=["AVG", "MIN", "MAX", "SUM"],
                    default="AVG",
                    required=i == 1,
                )

                definition.define_int_parameter(
                    f"slo{i}",
                    label=f"SLO (in basis points) {i}",
                    description="The SLO threshold in basis points (1% = 100 bps)",
                    required=i == 1,
                    default=9500,
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

            definition.define_object_type("SLOWorld", "SLO World")

            slo = definition.define_object_type("SLO", "SLO")
            slo.define_string_property("resourceType", "Resource Type")
            slo.define_string_property("metricName", "Metric Name")
            slo.define_numeric_property("sloThreshold", "SLO Threshold", None)
            slo.define_numeric_property("errorBudget", "Error Budget", Units.TIME.SECONDS)

            slo_attainment = definition.define_object_type("SLOAttainment", "SLO Attainment")
            slo_attainment.define_string_property("resourceName", "Resource Name")
            slo_attainment.define_metric("sloScore", "SLO Score", Units.RATIO.PERCENT)
            slo_attainment.define_metric("errorBudgetBurn", "Error Budget Burn", Units.TIME.SECONDS)
            slo_attainment.define_metric("errorBudgetRemaining", "Error Budget Remaining", Units.TIME.SECONDS)
            slo_attainment.define_metric("errorBudgetBurnPct", "Error Budget Burn", Units.RATIO.PERCENT)
            slo_attainment.define_metric("errorBudgetRemainingPct", "Error Budget Remaining", Units.RATIO.PERCENT)

            logger.debug(f"Returning adapter definition: {definition.to_json()}")
            return definition
        except Exception as e:
            logger.error("Unexpected adapter definition error")
            logger.exception(e)
            raise


def test(adapter_instance: AdapterInstance) -> TestResult:
    with Timer(logger, "Test"):
        result = TestResult()
        ops_client = adapter_instance.suite_api_client
        ops_client.get_token()
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
    logger.debug("Adapter Instance: %s", adapter_instance.get_json())
    with Timer(logger, "Collection"):
        try:
            # Log in and create SLOWorld object
            ops_client = adapter_instance.suite_api_client
            ops_client.get_token()
            result = CollectResult()
            slo_world = result.object(ADAPTER_KIND, "SLOWorld", "SLO World")

            # Iterate over configured SLOs
            for i in range(1, MAX_SLOS + 1):
                slo_name = adapter_instance.get_identifier_value(f"sloName{i}")
                logger.debug(f"Processing SLO {i}: {slo_name}")
                if not slo_name:
                    continue  # No more SLOs configured

                # Retrieve SLO configuration parameters
                threshold = float(adapter_instance.get_identifier_value(f"sloThreshold{i}"))
                resource_type = adapter_instance.get_identifier_value(f"sloResourceType{i}")
                metric_name = adapter_instance.get_identifier_value(f"sloMetric{i}")
                lookback = int(adapter_instance.get_identifier_value(f"sloLookbackPeriod{i}"))
                condition = adapter_instance.get_identifier_value(f"sloCondition{i}")
                rollup = adapter_instance.get_identifier_value(f"sloRollupType{i}")
                interval = int(adapter_instance.get_identifier_value(f"rollupInterval{i}"))
                slo = int(adapter_instance.get_identifier_value(f"slo{i}"))
                slo_type = adapter_instance.get_identifier_value(f"sloType{i}")

                # Calculate start times for different SLO periods 
                now = datetime.now()
                slo_length, start_time = slo_type_to_times(lookback, now, slo_type)
                logger.debug(f"SLO {slo_name}: start_time={datetime.fromtimestamp(start_time/1000)}, slo_length={slo_length}, slo_type={slo_type}")

                # Calculate the error budget
                error_budget_seconds = slo_length * (1.0-(slo / 10000.0))
                logger.debug(f"SLO {slo_name}: error_budget_seconds={error_budget_seconds}, slo_length={slo_length}, slo={slo}")

                # Create SLO resource
                slo = result.object(ADAPTER_KIND, "SLO", f"{slo_name}")
                resource_type_property = Property("resourceType", resource_type)
                metric_name_property = Property("metricName", metric_name)
                error_budget_property = Property("errorBudget", error_budget_seconds)
                slo.add_property(resource_type_property)
                slo.add_property(metric_name_property)
                slo.add_parent(slo_world)
                slo.add_property(error_budget_property)
                op_below = condition.upper() == "BELOW"

                # Query for resources of the specified type
                page = 0
                res_query = {
                    "adapterKind": ["VMWARE"],
                    "resourceKind": [resource_type],
                }
                logger.debug("Querying for resources: %s", json.dumps(res_query))
                while True:
                    logger.debug(f"Querying resources page {page} for type {resource_type}")
                    response = ops_post(ops_client, f"/api/resources/query?page={page}&pageSize={PAGESIZE}", res_query)
                    page += 1
                    resources = response.get("resourceList", [])
                    if len(resources) == 0:
                        logger.warning(f"No resources found for type {resource_type}")
                        break
                    ids_to_names = {}
                    slo_attainment_objects = {}
                    for r in resources:
                        if "identifier" in r and "resourceKey" in r:
                            resource_name = r["resourceKey"].get("name", "unknown")
                            ids_to_names[r["identifier"]] = resource_name
                            slo_attainment_objects[r["identifier"]] = result.object(ADAPTER_KIND, "SLOAttainment", f"{slo_name}/{resource_name}")

                    logger.debug(f"Found {len(ids_to_names)} resources of type {resource_type}")

                    # TODO: Implement pagination if needed

                    # Query for metrics for the resources
                    query = {
                        "resourceId": list(ids_to_names.keys()),
                        "statKey": [metric_name],
                        "begin": start_time,
                        "rollUpType": rollup,
                        "intervalType": "MINUTES",
                        "intervalQuantifier": interval,
                    }
                    metrics = ops_post(ops_client, "/api/resources/stats/query", json=query)
                    if not metrics or "values" not in metrics:
                        continue

                    # Iterate over metrics for each resource
                    for metric_chunk in metrics.get("values", []):
                        resource_id = metric_chunk.get("resourceId")
                        name = ids_to_names.get(resource_id, resource_id)
                        slo_attainment = slo_attainment_objects.get(resource_id, None)
                        if not slo_attainment:
                            logger.warning(f"No SLO Attainment object found for resource ID {resource_id}")
                            continue
                        slo.add_child(slo_attainment)

                        breaches = 0
                        metric_list = metric_chunk.get("stat-list", {}).get("stat", [])

                        # Iterate through the metrics
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

                            # Count the number of time buckets we've been out of compliance
                            for value in data:
                                if value is None:
                                    continue
                                logger.debug(f"Evaluating value {value} against threshold {threshold}")
                                if (op_below and value < threshold) or (not op_below and value > threshold):
                                    breaches += 1

                            # Calculate metrics and add them to the result
                            total_intervals = timespan / (interval * 60000.0)
                            attainment = 100.0 * (
                                        1.0 - (breaches / total_intervals)) if total_intervals > 0 else 0.0
                            logger.debug(f"{name},{slo_name},{attainment:.2f}")
                            slo_score = Metric("sloScore", attainment)
                            burn = breaches * interval * 60
                            remaining = max(0, error_budget_seconds - burn)
                            error_budget_burn = Metric("errorBudgetBurn", burn)
                            error_budget_remaining = Metric("errorBudgetRemaining", remaining)
                            error_budget_burn_pct = Metric("errorBudgetBurnPct",
                                   (burn / error_budget_seconds) * 100 if error_budget_seconds > 0 else 0)
                            error_budget_remaining_pct = Metric("errorBudgetRemainingPct",
                                   (remaining / error_budget_seconds) * 100 if error_budget_seconds > 0 else 0)
                            slo_attainment.add_metric(error_budget_burn)
                            slo_attainment.add_metric(error_budget_remaining)
                            slo_attainment.add_metric(error_budget_burn_pct)
                            slo_attainment.add_metric(error_budget_remaining_pct)
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


def slo_type_to_times(lookback, now, slo_type):
    if slo_type == "Monthly":
        start_time = int(datetime(now.year, now.month, 1).timestamp() * 1000)
        slo_length = 30 * 86400
    elif slo_type == "Quarterly":
        start_time = int(datetime(now.year, ((now.month - 1) // 3) * 3 + 1, 1).timestamp() * 1000)
        slo_length = 90 * 86400
    else:
        start_time = int(time.time() - 86400 * lookback) * 1000
        slo_length = lookback * 60 * 60 * 24
    return slo_length, start_time

def ops_post(client, path, json):
    with client.post(path, json=json) as response:
        if response.status_code != 200:
            logger.error(f"Failed to retrieve metrics: {response.status_code} {response.text}")
            return None
        return response.json()


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
