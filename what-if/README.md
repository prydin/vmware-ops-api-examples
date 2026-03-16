# Run ad-hoc What-If analysis

What-if analysis API call. This is a simple example of how the what-if analysis API can be used to dertermine if a workload would fit.
## Description
This example creates a temporary what-if scenario and runs a workload analysis. It then outputs information on whether the workload would
fit and what the capacity utilization would look like after placement.
## Usage

```
usage: python what-if.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -c CONFIG [-U]
```

### Arguments
```
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The address of the VCF Ops host
  -u USER, --user USER  The VCF Ops user
  -p PASSWORD, --password PASSWORD
                        The VCF Ops password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Ops authentication source. Default is Local
  -s SCENARIO, --scenario SCENARIO
                        The path to the scenario configuration file
  -d DATACENTER, --datacenter DATACENTER
                        The name of the datacenter to run the scenario in
  -c CLUSTER, --cluster CLUSTER
                        The name of the cluster to run the scenario in
                        (optional)
  -U, --unsafe          Skip certificate checking (this is unsafe!)
```

## Example 
```commandline
python what-if.py -H myhost.com -u admin -p secret -s good-scenario.yaml -d vcf-lab-dc -c vcf-lab-mgmt --unsafe
```
### Scenario file
```yaml
manualVmConfig:
    count: 2
    cpu: 4
    memory: 8
    storage: 100
    memoryUtilization: 50
    cpuUtilization: 50
    storageUtilization: 50
    cpuUtilizationGrowthRate: 10
    memoryUtilizationGrowthRate: 10
    storageUtilizationGrowthRate: 10
commonUtilizationGrowthRate: 10
```
### Output
```text
The scenario will not fit
*** Cluster vcf-lab-mgmt summary ***
CPU after applying scenario: 0.0 MHz
Memory after applying scenario: 477.6566072583263 GB
Storage after applying scenario: 0.0 GB
```
