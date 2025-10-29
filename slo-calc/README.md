# Calculate SLO attainment

Example of how to calculate SLO attainment based on a threshold

## Description
This example analyzes a set of metrics and measures for how many intervals they have been outside a specified range. 
These intervals are then summed up and divided by the total number of intervals (the lookback period) to obtain
a SLO attainment metrics. The data is printed to stdout as a comma-separated stream (CVS).

The definition of the SLOs are contained in a YAML-based configuration file. See below for an example.

## Usage

```
python getmetric.py usage: slo-calc [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -c CONFIG [-U]
```

### Arguments
```
   -h, --help                       Show this help message and exit
  -H HOST, --host HOST              The address of the VCF Ops host
  -u USER, --user USER              The VCF Ops user
  -p PASSWORD, --password  PASSWORD The VCF Ops password
  -a AUTHSOURCE, --authsource AUTHSOURCE The VCF Ops authentication source. Default is Local
  -c CONFIG, --config CONFIG        Path to the config file
  -U, --unsafe                      Skip certificate checking (this is unsafe!)
```

## Example 
```commandline
python slo-calc.py -H ops.example.com -u admin -p secret -U -c slo.yaml 
```
### Config file
```yaml
slo_list:
  - name: ClusterCPUContention            # Name of SLO
    resourceType: ClusterComputeResource  # Resource type to check
    metric: cpu|capacity_contentionPct    # Metric to check
    threshold: 3                          # Breach threshold
    operator: gt                          # Comparison type (LT, GT)
    interval: 5                           # Rollup interval in minutes
    rollup: MAX                           # Rollup type. (MIN, MAX, AVG)
  - name: HostCPUContention
    resourceType: HostSystem
    metric: cpu|capacity_contentionPct
    threshold: 3
    operator: gt
    interval: 5
    rollup: MAX
  - name: VMCPUContention
    resourceType: VirtualMachine
    metric: cpu|capacity_contentionPct
    threshold: 3
    operator: gt
    interval: 5
    rollup: MAX
  - name: ClusterMemoryContention
    resourceType: ClusterComputeResource
    metric: mem|host_contentionPct
    threshold: 3
    operator: gt
    interval: 5
    rollup: MAX
```
### Output
```text
wld-01,ClusterCPUContention,100.0
vcf-lab-mgmt,ClusterCPUContention,98.75222816399287
esxn-02.vcf-lab.local,HostCPUContention,100.0
esxn-03.vcf-lab.local,HostCPUContention,100.0
esx-02.vcf-lab.local,HostCPUContention,99.64349376114082
esxn-02.vcf-lab.local,HostCPUContention,100.0
esxn-01.vcf-lab.local,HostCPUContention,100.0
esx-01.vcf-lab.local,HostCPUContention,24.064171122994647
esxn-01.vcf-lab.local,HostCPUContention,100.0
esxn-03.vcf-lab.local,HostCPUContention,100.0
esx-03.vcf-lab.local,HostCPUContention,98.93048128342245
edge-02,VMCPUContention,99.8217468805704
vc-01,VMCPUContention,61.49732620320856
nsx-app-01,VMCPUContention,46.702317290552585
vCLS-03000200-0400-0500-0006-000700080009,VMCPUContention,100.0
edge-01,VMCPUContention,99.64349376114082
vc-wld-01,VMCPUContention,99.00332225913621
vcfa-mgmt-qq2pf,VMCPUContention,89.66131907308377
vCLS-9b530042-890e-8ea1-9693-45e55844a1a9,VMCPUContention,100.0
desktop-01,VMCPUContention,90.9090909090909
vCLS-419a4d56-8ed7-5f52-b137-262c16ad3e06,VMCPUContention,100.0
esxn-03,VMCPUContention,100.0
esxn-01,VMCPUContention,99.64349376114082
mc-01,VMCPUContention,100.0
nsx-wld-01-app,VMCPUContention,4.081632653061229
nsx-front-01,VMCPUContention,100.0
vCLS-9b530042-890e-8ea1-9693-45e55844a1a9,VMCPUContention,100.0
depot-01,VMCPUContention,92.15686274509804
coll-01,VMCPUContention,100.0
vCLS-a8560042-7d53-257d-4d1c-d23e68bbbd3b,VMCPUContention,100.0
ops-01,VMCPUContention,94.11764705882352
vCLS-00000000-0000-0000-0000-000000000000,VMCPUContention,100.0
esxn-02,VMCPUContention,99.8217468805704
opsfm-01,VMCPUContention,100.0
vcf-installer-01,VMCPUContention,100.0
wld-01,ClusterMemoryContention,100.0
vcf-lab-mgmt,ClusterMemoryContention,100.0
```
