# Telegraf Forwarder

Example of how metrics can be forwarded to Telegraf for futher processing. The metrics are defined in a
config file as described below 

## Usage

```
python telegraf-forwarder [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE]
                          [-k ADAPTERKIND] -r RESOURCEKIND -m METRICS
                          [-P PORT]
```

### Arguments
```
 optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -P PASSWORDFILE, --passwordfile PASSWORDFILE
  -a AUTHSOURCE, --authsource AUTHSOURCE
  -c CONFIG, --config CONFIG
```

## Config file example
```yaml
- resourceQuery:
    adapterKind: ["VMWARE"]
    resourceKind: ["HostSystem"]
  metrics:
    - cpu|demandmhz
    - cpu|demandPct
- resourceQuery:
    adapterKind: ["VMWARE"]
    resourceKind: ["VirtualMachine"]
  metrics:
    - cpu|demandmhz
    - cpu|demandPct
    - cpu|usage
    - mem|usage_average
    - mem|host_demand
    - mem|guest_demand
    - mem|density
```

## Example 
```commandline
python -H example.local -u admin -p secret -r VirtualMachine -c config.yaml
```
