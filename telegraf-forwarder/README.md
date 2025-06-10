# Prometheus Scraper

Example of getting the latest value of a single metric for a resource. To be useful 
in a real-life scenario, the code would have to be modified to support more thatn 
1000 resources and to allow chunked queries.

## Usage

```
python prometheus-scraper [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE]
                          [-k ADAPTERKIND] -r RESOURCEKIND -m METRICS
                          [-P PORT]
```

### Arguments
```
 -h, --help            show this help message and exit
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -a AUTHSOURCE, --authsource AUTHSOURCE
  -k ADAPTERKIND, --adapterkind ADAPTERKIND
  -r RESOURCEKIND, --resourcekind RESOURCEKIND
  -m METRICS, --metrics METRICS
  -P PORT, --port PORT
```

## Example 
```commandline
python -H example.local -u admin -p secret -r VirtualMachine -m cpu|demandpct,cpu|demandmhz 
```
