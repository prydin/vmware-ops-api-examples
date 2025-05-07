# Run a report

Example of running a report and downloading the result

## Usage

```
python generate_report.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [-k ADAPTERKIND] -r RESOURCEKIND -n RESOURCENAME -R RESROURCENAME
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
  -R REPORTNAME --reportname REPORTNAME
 
```

## Example 
```commandline
python generate_report.py -H vrops.example.com -u admin -p secret -r VirtualMachine -R "My Report" 
```
