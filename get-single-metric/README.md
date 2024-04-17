# Get Single Metric

Example of getting the latest value of a single metric for a resource.

## Usage

```
python getmetric.py getmetric [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [-k ADAPTERKIND] -r RESOURCEKIND -n RESOURCENAME -m METRIC [-U UNIT]
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
  -n RESOURCENAME, --resourcename RESOURCENAME
  -m METRIC, --metric METRIC
  -U UNIT, --unit UNIT
```

## Example 
```commandline
python getmetric.py -H vrops.example.com -u admin -p secret -r VirtualMachine -n my-vm -m "CPU|Demand" -U "%" 
```
