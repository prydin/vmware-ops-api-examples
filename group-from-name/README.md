# Import groups

Example of creating custom groups based on a simple CSV file.

## Usage

```
python groups-from-name.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -A
                        APPREGEX [-f FILTERREGEX] [-U] [-l LIMIT] [-F]
```

### Arguments
```
usage: groups-from-name [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -A
                        APPREGEX [-f FILTERREGEX] [-U] [-l LIMIT] [-F]

Creates groups based on VM names

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The VCF Operations host
  -u USER, --user USER  The VCF Operations user
  -p PASSWORD, --password PASSWORD
                        The VCF Operations password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Operations authentication source
  -A APPREGEX, --appregex APPREGEX
                        Regexp for obtaining application name from VM name
  -f FILTERREGEX, --filterregex FILTERREGEX
                        Regexp to filter VMs by name (defauls is all VMs)
  -U, --unsafe          Ignore certificate validation errors. Not recommended
                        in production
  -l LIMIT, --limit LIMIT
                        Limit number of VMs to process. Useful for
                        testing/debugging
  -F, --force           Force replacement of existing groups
```

## Example
```bash
python group-from-name.py -H 192.168.1.220 -u admin -h -p secret -f "^[^-]+-[A-Za-z]+" -A "^(.+)-.*" --unsafe
``` 
