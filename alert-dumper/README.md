# Relationship Builder Example

Example script for exporting details about alert definitions and symptom definitions to a CSV file.

## Description
Exports alert definitions and symptom definitions from VCF Operations to a CSV file.
## Usage

```
usage: alert-dumper [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [-s]
                    [-o OUTPUT] [-U]
```

### Arguments
```
options:
 -h, --help            show this help message and exit
  -H HOST, --host HOST  The address of the VCF Ops host
  -u USER, --user USER  The VCF Ops user
  -p PASSWORD, --password PASSWORD
                        The VCF Ops password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Ops authentication source. Default is Local
  -s, --symptoms        If set, dump symptoms instead of alerts
  -o OUTPUT, --output OUTPUT
                        Output file
  -U, --unsafe          Skip certificate checking (this is unsafe!)
```

## Example

```commandline
python alert-dumper.py -H 192.168.1.220 -u admin -p secret --unsafe -s -o symptoms.csv
```