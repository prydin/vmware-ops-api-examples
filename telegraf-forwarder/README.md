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

## Telegraf config example
```toml
# Read metrics from one or more commands that can output to stdout
[agent]
  interval = "5m"

[[inputs.exec]]
  ## Commands array
  commands = [ "python3 telegraf-forwarder.py -H $VROPS_HOST -u user -P /somwewhere/keys/vrops.txt -c config.yaml" ]
  data_format = "influx"
  timeout = "4m"

[[outputs.prometheus_client]]
  listen = ":8888"
  metric_batch_size = 1000
  metric_buffer_limit = 100000
  expiration_interval = "0s"

  [[processors.printer]]
```

